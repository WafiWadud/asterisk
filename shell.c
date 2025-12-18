#define _GNU_SOURCE
#include <ctype.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <readline/history.h>
#include <readline/readline.h>

// =====================
// Variables
// =====================
typedef struct Var {
  char *name;
  char *value;
  struct Var *next;
} Var;

static Var *vars = NULL;

void set_var(const char *name, const char *value) {
  for (Var *v = vars; v; v = v->next) {
    if (strcmp(v->name, name) == 0) {
      free(v->value);
      v->value = strdup(value);
      setenv(name, value, 1);
      return;
    }
  }
  Var *v = malloc(sizeof(Var));
  v->name = strdup(name);
  v->value = strdup(value);
  v->next = vars;
  vars = v;
  setenv(name, value, 1);
}

const char *get_var(const char *name) {
  for (Var *v = vars; v; v = v->next)
    if (strcmp(v->name, name) == 0)
      return v->value;
  const char *env = getenv(name);
  return env ? env : "";
}

// =====================
// Command substitution
// =====================
char *substitute_commands(const char *input) {
  char *out = malloc(strlen(input) * 2 + 1);
  size_t j = 0;
  for (size_t i = 0; input[i]; i++) {
    if ((input[i] == '`') || (input[i] == '$' && input[i + 1] == '(')) {
      int backtick = (input[i] == '`');
      i += backtick ? 1 : 2;
      size_t start = i;
      int depth = 1;
      while (input[i] && depth > 0) {
        if (!backtick && input[i] == '(')
          depth++;
        else if (!backtick && input[i] == ')')
          depth--;
        else if (backtick && input[i] == '`')
          break;
        i++;
      }
      size_t cmd_len = i - start;
      char *cmd = strndup(input + start, cmd_len);

      FILE *fp = popen(cmd, "r");
      free(cmd);
      if (!fp)
        continue;

      char buf[512];
      while (fgets(buf, sizeof(buf), fp)) {
        size_t len = strlen(buf);
        if (len && buf[len - 1] == '\n')
          buf[len - 1] = 0;
        j += sprintf(out + j, "%s", buf);
      }
      pclose(fp);
      if (!backtick)
        ;
      else
        i++;
    } else {
      out[j++] = input[i];
    }
  }
  out[j] = '\0';
  return out;
}

// =====================
// Variable expansion
// =====================
char *expand_variables(const char *input) {
  size_t len = strlen(input);
  char *out = malloc(len * 2 + 1);
  size_t j = 0;

  for (size_t i = 0; i < len; i++) {
    if (input[i] == '\\') {
      if (input[i + 1])
        out[j++] = input[++i];
      continue;
    }
    if (input[i] == '$') {
      i++;
      if (input[i] == '{') {
        i++;
        size_t start = i;
        while (input[i] && input[i] != '}')
          i++;
        if (input[i] == '}') {
          size_t nlen = i - start;
          char name[256];
          strncpy(name, input + start, nlen);
          name[nlen] = '\0';
          const char *val = get_var(name);
          j += sprintf(out + j, "%s", val);
        }
      } else if (isalpha((unsigned char)input[i]) || input[i] == '_') {
        size_t start = i;
        while (isalnum((unsigned char)input[i]) || input[i] == '_')
          i++;
        size_t nlen = i - start;
        char name[256];
        strncpy(name, input + start, nlen);
        name[nlen] = '\0';
        const char *val = get_var(name);
        j += sprintf(out + j, "%s", val);
        i--;
      } else {
        out[j++] = '$';
        i--;
      }
    } else {
      out[j++] = input[i];
    }
  }

  out[j] = '\0';
  return out;
}

// Check if a command is a variable assignment
int is_variable_assignment(const char *cmd) {
  if (!cmd || !*cmd)
    return 0;
  if (cmd[0] == '$')
    return 0; // Don't treat $... as assignment

  char *eq = strchr(cmd, '=');
  if (!eq)
    return 0;

  // Check if there's text before the '='
  for (const char *p = cmd; p < eq; p++) {
    if (!isalnum((unsigned char)*p) && *p != '_') {
      return 0;
    }
  }
  return 1;
}

// =====================
// Tokenize
// =====================
char **tokenize(const char *line) {
  size_t size = 8, i = 0;
  char **tokens = malloc(size * sizeof(char *));
  const char *delim = " \t\r\n";
  char *copy = strdup(line);
  char *token = strtok(copy, delim);
  while (token) {
    if (i + 1 >= size) {
      size *= 2;
      tokens = realloc(tokens, size * sizeof(char *));
    }
    tokens[i++] = strdup(token);
    token = strtok(NULL, delim);
  }
  tokens[i] = NULL;
  free(copy);
  return tokens;
}

void free_tokens(char **tokens) {
  if (!tokens)
    return;
  for (int i = 0; tokens[i]; i++)
    free(tokens[i]);
  free(tokens);
}

// =====================
// Globbing expansion
// =====================
char **expand_globs(char **tokens) {
  glob_t globbuf;
  char **expanded = NULL;
  size_t total = 0;

  for (size_t i = 0; tokens[i]; i++) {
    memset(&globbuf, 0, sizeof(globbuf));
    int ret = glob(tokens[i], GLOB_NOCHECK | GLOB_TILDE, NULL, &globbuf);
    for (size_t j = 0; j < globbuf.gl_pathc; j++) {
      expanded = realloc(expanded, sizeof(char *) * (total + 2));
      expanded[total++] = strdup(globbuf.gl_pathv[j]);
    }
    globfree(&globbuf);
  }

  if (expanded)
    expanded[total] = NULL;
  return expanded ? expanded : tokens;
}

// =====================
// Execute commands with pipes and redirections
// =====================
void run_command(char **argv) {
  if (!argv[0])
    return;

  // Handle variable assignments in the parent process
  if (strchr(argv[0], '=') && argv[0][0] != '$') {
    char *eq = strchr(argv[0], '=');
    *eq = 0;
    char *name = argv[0];
    char *val = eq + 1;

    // Handle arithmetic expansion $[expression]
    if (val[0] == '$' && val[1] == '[') {
      char *expr_start = val + 2; // Skip "$["
      size_t len = strlen(expr_start);
      if (len > 0 && expr_start[len - 1] == ']') {
        expr_start[len - 1] = '\0'; // Remove trailing ']'

        // Expand any variables in the expression first
        char *expanded_expr = expand_variables(expr_start);

        // Simple arithmetic evaluation
        char *ptr = expanded_expr;
        long result = 0;
        long current = 0;
        char op = '+';
        int has_value = 0;

        while (*ptr) {
          // Skip whitespace
          while (*ptr == ' ')
            ptr++;

          if (*ptr >= '0' && *ptr <= '9') {
            // Parse number
            current = strtol(ptr, &ptr, 10);
            has_value = 1;
          } else if (*ptr == '+' || *ptr == '-' || *ptr == '*' || *ptr == '/' ||
                     *ptr == '%') {
            if (has_value) {
              // Apply current operation
              switch (op) {
              case '+':
                result += current;
                break;
              case '-':
                result -= current;
                break;
              case '*':
                result *= current;
                break;
              case '/':
                if (current != 0)
                  result /= current;
                break;
              case '%':
                if (current != 0)
                  result %= current;
                break;
              }
              current = 0;
              has_value = 0;
            }
            op = *ptr;
            ptr++;
          } else {
            // Skip unknown characters
            ptr++;
          }
        }

        // Apply final operation
        if (has_value) {
          switch (op) {
          case '+':
            result += current;
            break;
          case '-':
            result -= current;
            break;
          case '*':
            result *= current;
            break;
          case '/':
            if (current != 0)
              result /= current;
            break;
          case '%':
            if (current != 0)
              result %= current;
            break;
          }
        }

        char buf[64];
        snprintf(buf, sizeof(buf), "%ld", result);
        set_var(name, buf);
        free(expanded_expr);
        return;
      }
    }

    // Regular variable assignment
    char *expanded_val = expand_variables(val);
    set_var(name, expanded_val);
    free(expanded_val);
    return;
  }

  // For non-variable commands, execute in child process
  int pipefd[2];
  int has_pipe = 0;
  int split = -1;
  for (int i = 0; argv[i]; i++) {
    if (strcmp(argv[i], "|") == 0) {
      argv[i] = NULL;
      split = i;
      has_pipe = 1;
      break;
    }
  }

  if (has_pipe)
    pipe(pipefd);

  pid_t pid = fork();
  if (pid == 0) {
    if (has_pipe) {
      dup2(pipefd[1], STDOUT_FILENO);
      close(pipefd[0]);
      close(pipefd[1]);
    }

    for (int i = 0; argv[i]; i++) {
      if (strcmp(argv[i], ">") == 0 || strcmp(argv[i], ">>") == 0) {
        int append = (argv[i][1] == '>');
        argv[i] = NULL;
        int fd = open(argv[i + 1],
                      O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC), 0644);
        dup2(fd, STDOUT_FILENO);
        close(fd);
      } else if (strcmp(argv[i], "<") == 0) {
        argv[i] = NULL;
        int fd = open(argv[i + 1], O_RDONLY);
        dup2(fd, STDIN_FILENO);
        close(fd);
      }
    }

    execvp(argv[0], argv);
    perror("execvp");
    exit(1);
  } else if (pid > 0) {
    if (has_pipe) {
      close(pipefd[1]);
      pid_t pid2 = fork();
      if (pid2 == 0) {
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        run_command(&argv[split + 1]);
        exit(0);
      }
      close(pipefd[0]);
      waitpid(pid, NULL, 0);
      waitpid(pid2, NULL, 0);
    } else {
      waitpid(pid, NULL, 0);
    }
  } else {
    perror("fork");
  }
}

// =====================
// Condition evaluation (numeric + string)
// =====================
int eval_condition(const char *cond) {
  char *expanded = expand_variables(cond);
  char left[256], op[3], right[256];
  int result = 0;

  if (sscanf(expanded, "%255s %2s %255s", left, op, right) == 3) {
    char *endptr1, *endptr2;
    long a = strtol(left, &endptr1, 10);
    long b = strtol(right, &endptr2, 10);
    int numeric = (*endptr1 == '\0' && *endptr2 == '\0');

    if (numeric) {
      if (strcmp(op, "==") == 0)
        result = (a == b);
      else if (strcmp(op, "!=") == 0)
        result = (a != b);
      else if (strcmp(op, "<") == 0)
        result = (a < b);
      else if (strcmp(op, "<=") == 0)
        result = (a <= b);
      else if (strcmp(op, ">") == 0)
        result = (a > b);
      else if (strcmp(op, ">=") == 0)
        result = (a >= b);
    } else {
      if (strcmp(op, "==") == 0)
        result = (strcmp(left, right) == 0);
      else if (strcmp(op, "!=") == 0)
        result = (strcmp(left, right) != 0);
    }
  } else if (strcasecmp(expanded, "true") == 0)
    result = 1;
  else if (strcasecmp(expanded, "false") == 0)
    result = 0;

  free(expanded);
  return result;
}

// =====================
// Flow control one-liners
// =====================
void execute_flow(const char *line) {
  if (strncmp(line, "repeat-until", 12) == 0) {
    // Create a modifiable copy of the input line
    char *line_copy = strdup(line);
    if (!line_copy) {
      perror("strdup");
      return;
    }

    // Skip "repeat-until "
    char *p = line_copy + 12;
    while (isspace((unsigned char)*p))
      p++;

    // Check for (
    if (*p != '(') {
      fprintf(stderr, "Syntax error: expected '('\n");
      free(line_copy);
      return;
    }
    p++; // Skip '('

    // Find closing ')'
    char *cond_start = p;
    char *cond_end = strchr(p, ')');
    if (!cond_end) {
      fprintf(stderr, "Syntax error: expected ')'\n");
      free(line_copy);
      return;
    }
    *cond_end = '\0'; // Null-terminate condition

    // Extract condition and commands
    char *cond_str = strdup(cond_start);
    if (!cond_str) {
      perror("strdup");
      free(line_copy);
      return;
    }

    char *commands_start = cond_end + 1;
    while (isspace((unsigned char)*commands_start))
      commands_start++;

    char *commands_str = strdup(commands_start);
    if (!commands_str) {
      perror("strdup");
      free(line_copy);
      free(cond_str);
      return;
    }

    // Loop until condition is true
    while (1) {
      // Execute commands block (split by ;)
      if (*commands_str) {
        char *cmd_copy = strdup(commands_str);
        if (!cmd_copy) {
          perror("strdup");
          break;
        }

        char *part = strtok(cmd_copy, ";");
        while (part) {
          // Trim leading/trailing whitespace
          char *start = part;
          while (isspace((unsigned char)*start))
            start++;

          char *end = start + strlen(start) - 1;
          while (end > start && isspace((unsigned char)*end))
            end--;
          *(end + 1) = '\0';

          if (*start) {
            char *subbed = substitute_commands(start);
            char *expanded = expand_variables(subbed);
            free(subbed);

            char **tokens = tokenize(expanded);
            if (tokens && tokens[0]) {
              char **globbed = expand_globs(tokens);
              run_command(globbed);
              free_tokens(globbed);
            }
            free_tokens(tokens);
            free(expanded);
          }

          part = strtok(NULL, ";");
        }
        free(cmd_copy);
      }

      // Evaluate condition after executing
      char *expanded_cond = expand_variables(cond_str);
      int condition_result = eval_condition(expanded_cond);
      free(expanded_cond);

      if (condition_result) {
        break;
      }
    }

    // Cleanup
    free(commands_str);
    free(cond_str);
    free(line_copy);

  } else if (strncmp(line, "repeat ", 7) == 0) {
    int times;
    char commands[1024];
    if (sscanf(line, "repeat %d %1023[^\n]", &times, commands) == 2) {
      for (int i = 0; i < times; i++) {
        char *cmd_copy = strdup(commands);
        char *part = strtok(cmd_copy, ";");
        while (part) {
          // Remove leading/trailing whitespace from command
          while (*part == ' ')
            part++;
          char *end = part + strlen(part) - 1;
          while (end > part && *end == ' ')
            end--;
          *(end + 1) = '\0';

          if (strlen(part) > 0) {
            char *subbed = substitute_commands(part);
            char *expanded = expand_variables(subbed);
            free(subbed);

            char **tokens = tokenize(expanded);
            if (tokens && tokens[0]) {
              char **globbed = expand_globs(tokens);
              run_command(globbed);
              free_tokens(globbed);
            }
            free_tokens(tokens);
            free(expanded);
          }

          part = strtok(NULL, ";");
        }
        free(cmd_copy);
      }
    }
  } else if (strncmp(line, "if", 2) == 0) {
    // Make a copy since we need to modify the string
    char *line_copy = strdup(line);
    char *else_pos = strstr(line_copy, "; else");
    if (else_pos) {
      *else_pos = '\0';
      char *else_cmd = else_pos + 6;
      char cond[256], then_cmd[512];
      if (sscanf(line_copy, "if (%255[^)]) %511[^\n]", cond, then_cmd) == 2) {
        // Re-expand condition in case it contains variables
        char *expanded_cond = expand_variables(cond);
        if (eval_condition(expanded_cond)) {
          free(expanded_cond);
          char *subbed = substitute_commands(then_cmd);
          char *expanded = expand_variables(subbed);
          free(subbed);
          char **tokens = tokenize(expanded);
          if (tokens && tokens[0]) {
            char **globbed = expand_globs(tokens);
            run_command(globbed);
            free_tokens(globbed);
          }
          free_tokens(tokens);
          free(expanded);
        } else {
          free(expanded_cond);
          char *subbed = substitute_commands(else_cmd);
          char *expanded = expand_variables(subbed);
          free(subbed);
          char **tokens = tokenize(expanded);
          if (tokens && tokens[0]) {
            char **globbed = expand_globs(tokens);
            run_command(globbed);
            free_tokens(globbed);
          }
          free_tokens(tokens);
          free(expanded);
        }
      }
    } else {
      // Handle if without else
      char cond[256], then_cmd[512];
      if (sscanf(line_copy, "if (%255[^)]) %511[^\n]", cond, then_cmd) == 2) {
        char *expanded_cond = expand_variables(cond);
        if (eval_condition(expanded_cond)) {
          free(expanded_cond);
          char *subbed = substitute_commands(then_cmd);
          char *expanded = expand_variables(subbed);
          free(subbed);
          char **tokens = tokenize(expanded);
          if (tokens && tokens[0]) {
            char **globbed = expand_globs(tokens);
            run_command(globbed);
            free_tokens(globbed);
          }
          free_tokens(tokens);
          free(expanded);
        } else {
          free(expanded_cond);
        }
      }
    }
    free(line_copy);
  } else {
    char *subbed = substitute_commands(line);
    char *expanded = expand_variables(subbed);
    free(subbed);
    char **tokens = tokenize(expanded);
    if (tokens && tokens[0]) {
      char **globbed = expand_globs(tokens);
      run_command(globbed);
      free_tokens(globbed);
    }
    free_tokens(tokens);
    free(expanded);
  }
}

// =====================
// Main
// =====================
int main(void) {
  printf("Asterix SHell, v0.8\n");
  using_history();

  while (1) {
    char *input = readline("asterix> ");
    if (!input)
      break;
    if (strcasecmp(input, "quit") == 0 || strcasecmp(input, "exit") == 0) {
      free(input);
      break;
    }

    if (*input)
      add_history(input);

    execute_flow(input);
    free(input);
  }

  printf("Goodbye!\n");
  return 0;
}

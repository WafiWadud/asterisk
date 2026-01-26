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

#ifdef EDITLINE_ENABLED
#include <editline/readline.h>
#else
#define READLINE_ENABLED
#endif

#ifdef READLINE_ENABLED
#include <readline/history.h>
#include <readline/readline.h>
#endif

// =====================
// Macros & Constants
// =====================
#define BUFFER_SIZE 4096
#define MAX_TOKENS 256
#define MAX_VAR_NAME 256

// =====================
// Variable Storage
// =====================
typedef struct Var {
  char *name;
  char *value;
  struct Var *next;
} Var;

static Var *vars = NULL;

void free_vars(void) {
  while (vars) {
    Var *tmp = vars;
    vars = vars->next;
    free(tmp->name);
    free(tmp->value);
    free(tmp);
  }
}

void set_var(const char *name, const char *value) {
  if (!name || !value)
    return;

  for (Var *v = vars; v; v = v->next) {
    if (strcmp(v->name, name) == 0) {
      free(v->value);
      v->value = strdup(value);
      setenv(name, value, 1);
      return;
    }
  }

  Var *v = malloc(sizeof(Var));
  if (!v)
    return;
  v->name = strdup(name);
  v->value = strdup(value);
  v->next = vars;
  vars = v;
  setenv(name, value, 1);
}

const char *get_var(const char *name) {
  if (!name)
    return "";

  for (Var *v = vars; v; v = v->next)
    if (strcmp(v->name, name) == 0)
      return v->value;

  const char *env = getenv(name);
  return env ? env : "";
}

// =====================
// String Utilities
// =====================
char *safe_strndup(const char *str, size_t len) {
  if (!str)
    return calloc(1, 1);
  char *out = malloc(len + 1);
  if (!out)
    return NULL;
  strncpy(out, str, len);
  out[len] = '\0';
  return out;
}

void trim_string(char *str) {
  if (!str || !*str)
    return;

  // Trim leading
  size_t start = 0;
  while (isspace((unsigned char)str[start]))
    start++;

  // Trim trailing
  size_t end = strlen(str);
  while (end > start && isspace((unsigned char)str[end - 1]))
    end--;

  // Move
  if (start > 0)
    memmove(str, str + start, end - start);
  str[end - start] = '\0';
}

// =====================
// Command Substitution
// =====================
char *substitute_commands(const char *input) {
  if (!input)
    return calloc(1, 1);

  char *out = malloc(BUFFER_SIZE);
  if (!out)
    return calloc(1, 1);

  size_t out_len = BUFFER_SIZE;
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

      char *cmd = safe_strndup(input + start, i - start);
      if (!cmd)
        continue;

      FILE *fp = popen(cmd, "r");
      free(cmd);
      if (!fp)
        continue;

      char buf[512];
      while (fgets(buf, sizeof(buf), fp)) {
        size_t len = strlen(buf);
        if (len && buf[len - 1] == '\n')
          buf[len - 1] = 0;

        // Ensure buffer has space
        while (j + len >= out_len) {
          out_len *= 2;
          out = realloc(out, out_len);
          if (!out) {
            pclose(fp);
            return calloc(1, 1);
          }
        }

        memcpy(out + j, buf, len);
        j += len;
      }
      pclose(fp);

      if (!backtick)
        ;
      else
        i++;
    } else {
      // Ensure buffer has space
      if (j + 1 >= out_len) {
        out_len *= 2;
        out = realloc(out, out_len);
        if (!out)
          return calloc(1, 1);
      }
      out[j++] = input[i];
    }
  }

  out[j] = '\0';
  return out;
}

// =====================
// Variable Expansion
// =====================
char *expand_variables(const char *input) {
  if (!input)
    return calloc(1, 1);

  char *out = malloc(BUFFER_SIZE);
  if (!out)
    return calloc(1, 1);

  size_t out_len = BUFFER_SIZE;
  size_t j = 0;
  size_t len = strlen(input);

  for (size_t i = 0; i < len; i++) {
    if (input[i] == '\\' && input[i + 1]) {
      if (j + 1 >= out_len) {
        out_len *= 2;
        out = realloc(out, out_len);
        if (!out)
          return calloc(1, 1);
      }
      out[j++] = input[++i];
      continue;
    }

    if (input[i] == '$') {
      i++;
      const char *val = NULL;

      if (input[i] == '{') {
        // ${VAR_NAME} format
        i++;
        size_t start = i;
        while (input[i] && input[i] != '}')
          i++;

        if (input[i] == '}') {
          char name[MAX_VAR_NAME];
          size_t nlen = i - start;
          if (nlen < MAX_VAR_NAME) {
            strncpy(name, input + start, nlen);
            name[nlen] = '\0';
            val = get_var(name);
          }
        }
      } else if (isalpha((unsigned char)input[i]) || input[i] == '_') {
        // $VAR_NAME format
        size_t start = i;
        while (isalnum((unsigned char)input[i]) || input[i] == '_')
          i++;

        char name[MAX_VAR_NAME];
        size_t nlen = i - start;
        if (nlen < MAX_VAR_NAME) {
          strncpy(name, input + start, nlen);
          name[nlen] = '\0';
          val = get_var(name);
        }
        i--;
      } else {
        // Not a variable reference
        if (j + 1 >= out_len) {
          out_len *= 2;
          out = realloc(out, out_len);
          if (!out)
            return calloc(1, 1);
        }
        out[j++] = '$';
        i--;
        continue;
      }

      if (val) {
        size_t val_len = strlen(val);
        while (j + val_len >= out_len) {
          out_len *= 2;
          out = realloc(out, out_len);
          if (!out)
            return calloc(1, 1);
        }
        memcpy(out + j, val, val_len);
        j += val_len;
      }
    } else {
      if (j + 1 >= out_len) {
        out_len *= 2;
        out = realloc(out, out_len);
        if (!out)
          return calloc(1, 1);
      }
      out[j++] = input[i];
    }
  }

  out[j] = '\0';
  return out;
}

// =====================
// Tokenization
// =====================
char **tokenize(const char *input) {
  if (!input || !*input)
    return calloc(1, sizeof(char *));

  char *copy = strdup(input);
  if (!copy)
    return calloc(1, sizeof(char *));

  char **tokens = malloc(MAX_TOKENS * sizeof(char *));
  if (!tokens) {
    free(copy);
    return calloc(1, sizeof(char *));
  }

  int count = 0;
  char *ptr = copy;
  char *token;

  while ((token = strtok(ptr, " \t")) && count < MAX_TOKENS - 1) {
    tokens[count++] = strdup(token);
    ptr = NULL;
  }
  tokens[count] = NULL;

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
// Glob Expansion
// =====================
char **expand_globs(char **tokens) {
  if (!tokens || !tokens[0])
    return tokens;

  char **result = malloc(MAX_TOKENS * sizeof(char *));
  if (!result)
    return tokens;

  int result_count = 0;
  glob_t globbuf;

  for (int i = 0; tokens[i] && result_count < MAX_TOKENS - 1; i++) {
    if (glob(tokens[i], GLOB_NOCHECK, NULL, &globbuf) == 0) {
      for (size_t j = 0; j < globbuf.gl_pathc && result_count < MAX_TOKENS - 1;
           j++) {
        result[result_count++] = strdup(globbuf.gl_pathv[j]);
      }
      globfree(&globbuf);
    } else {
      result[result_count++] = strdup(tokens[i]);
    }
  }
  result[result_count] = NULL;

  free_tokens(tokens);
  return result;
}

// =====================
// Condition Evaluation
// =====================
int eval_condition(const char *cond) {
  if (!cond || !*cond)
    return 0;

  char *copy = strdup(cond);
  if (!copy)
    return 0;

  trim_string(copy);

  int result = 0;

  // Simple comparisons
  if (strstr(copy, "==")) {
    char *left = copy;
    char *right = strstr(copy, "==") + 2;
    *strstr(copy, "==") = '\0';

    trim_string(left);
    trim_string(right);

    result = strcmp(left, right) == 0;
  } else if (strstr(copy, "!=")) {
    char *left = copy;
    char *right = strstr(copy, "!=") + 2;
    *strstr(copy, "!=") = '\0';

    trim_string(left);
    trim_string(right);

    result = strcmp(left, right) != 0;
  } else if (strstr(copy, "<=")) {
    char *left = copy;
    char *right = strstr(copy, "<=") + 2;
    *strstr(copy, "<=") = '\0';

    trim_string(left);
    trim_string(right);

    result = atoi(left) <= atoi(right);
  } else if (strstr(copy, ">=")) {
    char *left = copy;
    char *right = strstr(copy, ">=") + 2;
    *strstr(copy, ">=") = '\0';

    trim_string(left);
    trim_string(right);

    result = atoi(left) >= atoi(right);
  } else if (strstr(copy, "<")) {
    char *left = copy;
    char *right = strstr(copy, "<") + 1;
    *strstr(copy, "<") = '\0';

    trim_string(left);
    trim_string(right);

    result = atoi(left) < atoi(right);
  } else if (strstr(copy, ">")) {
    char *left = copy;
    char *right = strstr(copy, ">") + 1;
    *strstr(copy, ">") = '\0';

    trim_string(left);
    trim_string(right);

    result = atoi(left) > atoi(right);
  } else {
    // Check if string is not empty
    result = strlen(copy) > 0;
  }

  free(copy);
  return result;
}

// =====================
// Arithmetic Evaluation
// =====================
long eval_arithmetic(const char *expr) {
  if (!expr || !*expr)
    return 0;

  char *expanded = expand_variables(expr);
  char *copy = strdup(expanded);
  free(expanded);

  if (!copy)
    return 0;

  long result = 0;
  long current = 0;
  char op = '+';
  char *ptr = copy;

  while (*ptr) {
    // Skip whitespace
    while (*ptr == ' ')
      ptr++;

    if (*ptr >= '0' && *ptr <= '9') {
      current = strtol(ptr, &ptr, 10);
    } else if (*ptr == '+' || *ptr == '-' || *ptr == '*' || *ptr == '/' ||
               *ptr == '%') {
      // Apply previous operation
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
      op = *ptr;
      ptr++;
    } else {
      ptr++;
    }
  }

  // Apply final operation
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

  free(copy);
  return result;
}

// =====================
// Variable Assignment
// =====================
int is_variable_assignment(const char *cmd) {
  if (!cmd || !*cmd || cmd[0] == '$')
    return 0;

  char *eq = strchr(cmd, '=');
  if (!eq)
    return 0;

  // Check if all chars before '=' are valid var name chars
  for (const char *p = cmd; p < eq; p++) {
    if (!isalnum((unsigned char)*p) && *p != '_')
      return 0;
  }
  return 1;
}

void handle_assignment(const char *cmd) {
  if (!cmd || !*cmd)
    return;

  char *copy = strdup(cmd);
  if (!copy)
    return;

  char *eq = strchr(copy, '=');
  if (!eq) {
    free(copy);
    return;
  }

  *eq = '\0';
  char *name = copy;
  char *val = eq + 1;

  // Handle arithmetic expansion $[expression]
  if (val[0] == '$' && val[1] == '[') {
    char *expr_start = val + 2;
    size_t len = strlen(expr_start);
    if (len > 0 && expr_start[len - 1] == ']') {
      expr_start[len - 1] = '\0';
      long result = eval_arithmetic(expr_start);

      char buf[64];
      snprintf(buf, sizeof(buf), "%ld", result);
      set_var(name, buf);
    }
  } else {
    set_var(name, val);
  }

  free(copy);
}

// =====================
// Command Execution
// =====================
void run_command(char **args) {
  if (!args || !args[0])
    return;

  // Handle built-in commands
  if (strcmp(args[0], "cd") == 0) {
    const char *dir = args[1] ? args[1] : getenv("HOME");
    if (chdir(dir) != 0) {
      perror("cd");
    }
    return;
  }

  if (strcmp(args[0], "echo") == 0) {
    for (int i = 1; args[i]; i++) {
      printf("%s", args[i]);
      if (args[i + 1])
        printf(" ");
    }
    printf("\n");
    return;
  }

  // Fork and execute external command
  pid_t pid = fork();
  if (pid == 0) {
    // Child process
    execvp(args[0], args);
    perror(args[0]);
    exit(1);
  } else if (pid > 0) {
    // Parent process - wait for child
    int status;
    waitpid(pid, &status, 0);
  } else {
    perror("fork");
  }
}

// =====================
// Control Flow Execution
// =====================
void execute_flow(const char *line) {
  if (!line || !*line)
    return;

  // Skip leading whitespace
  while (isspace((unsigned char)*line))
    line++;

  if (!*line)
    return;

  // While loop
  if (strncmp(line, "while ", 6) == 0) {
    char *line_copy = strdup(line);
    if (!line_copy)
      return;

    char *p = line_copy + 6;
    while (isspace((unsigned char)*p))
      p++;

    if (*p != '(') {
      free(line_copy);
      return;
    }

    p++;
    char *cond_start = p;
    char *cond_end = strchr(p, ')');

    if (!cond_end) {
      free(line_copy);
      return;
    }

    *cond_end = '\0';
    char *cond_str = strdup(cond_start);
    char *commands_start = cond_end + 1;

    while (isspace((unsigned char)*commands_start))
      commands_start++;

    char *commands_str = strdup(commands_start);

    // Execute while loop
    while (1) {
      char *expanded_cond = expand_variables(cond_str);
      if (!eval_condition(expanded_cond)) {
        free(expanded_cond);
        break;
      }
      free(expanded_cond);

      // Execute commands
      char *cmd_copy = strdup(commands_str);
      char *part = strtok(cmd_copy, ";");
      while (part) {
        trim_string(part);
        if (*part) {
          char *subbed = substitute_commands(part);
          char *expanded = expand_variables(subbed);
          free(subbed);

          if (is_variable_assignment(expanded)) {
            handle_assignment(expanded);
          } else {
            char **tokens = tokenize(expanded);
            if (tokens && tokens[0]) {
              char **globbed = expand_globs(tokens);
              run_command(globbed);
              free_tokens(globbed);
            } else {
              free_tokens(tokens);
            }
          }
          free(expanded);
        }
        part = strtok(NULL, ";");
      }
      free(cmd_copy);
    }

    free(commands_str);
    free(cond_str);
    free(line_copy);
  }
  // If statement
  else if (strncmp(line, "if ", 3) == 0) {
    char *line_copy = strdup(line);
    if (!line_copy)
      return;

    char cond[256], then_cmd[512];
    if (sscanf(line_copy, "if (%255[^)]) %511[^\n]", cond, then_cmd) != 2) {
      free(line_copy);
      return;
    }

    char *expanded_cond = expand_variables(cond);
    int condition_result = eval_condition(expanded_cond);
    free(expanded_cond);

    if (condition_result) {
      char *subbed = substitute_commands(then_cmd);
      char *expanded = expand_variables(subbed);
      free(subbed);

      if (is_variable_assignment(expanded)) {
        handle_assignment(expanded);
      } else {
        char **tokens = tokenize(expanded);
        if (tokens && tokens[0]) {
          char **globbed = expand_globs(tokens);
          run_command(globbed);
          free_tokens(globbed);
        } else {
          free_tokens(tokens);
        }
      }
      free(expanded);
    }

    free(line_copy);
  }
  // Repeat statement
  else if (strncmp(line, "repeat ", 7) == 0) {
    int times;
    char commands[1024];
    if (sscanf(line, "repeat %d %1023[^\n]", &times, commands) == 2) {
      for (int i = 0; i < times; i++) {
        char *cmd_copy = strdup(commands);
        char *part = strtok(cmd_copy, ";");
        while (part) {
          trim_string(part);
          if (*part) {
            char *subbed = substitute_commands(part);
            char *expanded = expand_variables(subbed);
            free(subbed);

            if (is_variable_assignment(expanded)) {
              handle_assignment(expanded);
            } else {
              char **tokens = tokenize(expanded);
              if (tokens && tokens[0]) {
                char **globbed = expand_globs(tokens);
                run_command(globbed);
                free_tokens(globbed);
              } else {
                free_tokens(tokens);
              }
            }
            free(expanded);
          }
          part = strtok(NULL, ";");
        }
        free(cmd_copy);
      }
    }
  }
  // Regular command
  else {
    char *subbed = substitute_commands(line);
    char *expanded = expand_variables(subbed);
    free(subbed);

    if (is_variable_assignment(expanded)) {
      handle_assignment(expanded);
    } else {
      char **tokens = tokenize(expanded);
      if (tokens && tokens[0]) {
        char **globbed = expand_globs(tokens);
        run_command(globbed);
        free_tokens(globbed);
      } else {
        free_tokens(tokens);
      }
    }
    free(expanded);
  }
}

// =====================
// Main
// =====================
int main(void) {
  printf("Asterix SHell, v0.9\n");

#ifndef EDITLINE_ENABLED
  using_history();
#endif

  atexit(free_vars);

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

/**
 * Asterix SHell — D reimplementation
 * Compile with:
 *   ldc2 -betterC -O3 -release -boundscheck=off \
 *        -Lpath/to/editline -leditline \
 *        -of=ash shell.d
 *
 * Or with dmd:
 *   dmd -betterC -O -release -of=ash shell.d -L-leditline
 */

module shell;

// ---------------------------------------------------------------------------
// C bindings we need (betterC has no D runtime, so we bind everything manually)
// ---------------------------------------------------------------------------
extern (C) nothrow @nogc:

// --- libc ---
void* malloc(size_t n);
void* calloc(size_t nmemb, size_t size);
void* realloc(void* ptr, size_t n);
void  free(void* ptr);
char* strdup(const(char)* s);
char* strndup(const(char)* s, size_t n);
size_t strlen(const(char)* s);
int    strcmp(const(char)* a, const(char)* b);
int    strncmp(const(char)* a, const(char)* b, size_t n);
int    strcasecmp(const(char)* a, const(char)* b);
char*  strchr(const(char)* s, int c);
char*  strstr(const(char)* haystack, const(char)* needle);
char*  strncpy(char* dst, const(char)* src, size_t n);
void*  memcpy(void* dst, const(void)* src, size_t n);
void*  memmove(void* dst, const(void)* src, size_t n);
int    snprintf(char* buf, size_t size, const(char)* fmt, ...);
int    sscanf(const(char)* buf, const(char)* fmt, ...);
int    printf(const(char)* fmt, ...);
void   perror(const(char)* s);
int    isspace(int c);
int    isalpha(int c);
int    isalnum(int c);
long   strtol(const(char)* nptr, char** endptr, int base);
int    atoi(const(char)* s);
char*  getenv(const(char)* name);
int    setenv(const(char)* name, const(char)* value, int overwrite);
int    chdir(const(char)* path);
int    atexit(void function() func);

// --- process / POSIX ---
alias pid_t = int;
pid_t fork();
int   execvp(const(char)* file, char** argv);
int   waitpid(pid_t pid, int* status, int options);

// --- popen/pclose ---
struct FILE;
FILE* popen(const(char)* command, const(char)* type);
char* fgets(char* s, int size, FILE* stream);
int   pclose(FILE* stream);

// --- glob ---
struct glob_t {
    size_t   gl_pathc;
    char**   gl_pathv;
    size_t   gl_offs;
    // padding so struct size matches glibc (at least 4 pointer-width fields follow)
    void*[4] _pad;
}
enum GLOB_NOCHECK = 16;
int   glob(const(char)* pattern, int flags, void* errfunc, glob_t* pglob);
void  globfree(glob_t* pglob);

// --- strtok ---
char* strtok(char* str, const(char)* delim);

// --- editline ---
char* readline(const(char)* prompt);
void  add_history(const(char)* line);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
enum BUFFER_SIZE = 4096;
enum MAX_TOKENS  = 256;
enum MAX_VAR_NAME = 256;

// ---------------------------------------------------------------------------
// Variable storage  (intrusive singly-linked list, just like the C original)
// ---------------------------------------------------------------------------
struct Var {
    char* name;
    char* value;
    Var*  next;
}

static Var* vars = null;

void free_vars() nothrow @nogc {
    while (vars) {
        Var* tmp = vars;
        vars = vars.next;
        free(tmp.name);
        free(tmp.value);
        free(tmp);
    }
}

void set_var(const(char)* name, const(char)* value) nothrow @nogc {
    if (!name || !value) return;

    for (Var* v = vars; v; v = v.next) {
        if (strcmp(v.name, name) == 0) {
            free(v.value);
            v.value = strdup(value);
            setenv(name, value, 1);
            return;
        }
    }

    Var* v = cast(Var*) malloc(Var.sizeof);
    if (!v) return;
    v.name  = strdup(name);
    v.value = strdup(value);
    v.next  = vars;
    vars    = v;
    setenv(name, value, 1);
}

const(char)* get_var(const(char)* name) nothrow @nogc {
    if (!name) return "".ptr;

    for (Var* v = vars; v; v = v.next)
        if (strcmp(v.name, name) == 0)
            return v.value;

    const(char)* env = getenv(name);
    return env ? env : "".ptr;
}

// ---------------------------------------------------------------------------
// String utilities
// ---------------------------------------------------------------------------
char* safe_strndup(const(char)* str, size_t len) nothrow @nogc {
    if (!str) return cast(char*) calloc(1, 1);
    char* out_ = cast(char*) malloc(len + 1);
    if (!out_) return null;
    strncpy(out_, str, len);
    out_[len] = '\0';
    return out_;
}

void trim_string(char* str) nothrow @nogc {
    if (!str || !*str) return;

    size_t start = 0;
    while (isspace(cast(ubyte) str[start]))
        start++;

    size_t end = strlen(str);
    while (end > start && isspace(cast(ubyte) str[end - 1]))
        end--;

    if (start > 0)
        memmove(str, str + start, end - start);
    str[end - start] = '\0';
}

// ---------------------------------------------------------------------------
// Command substitution  — handles `...` and $(...)
// ---------------------------------------------------------------------------
char* substitute_commands(const(char)* input) nothrow @nogc {
    if (!input) return cast(char*) calloc(1, 1);

    char* out_ = cast(char*) malloc(BUFFER_SIZE);
    if (!out_) return cast(char*) calloc(1, 1);

    size_t out_len = BUFFER_SIZE;
    size_t j = 0;

    for (size_t i = 0; input[i]; i++) {
        if (input[i] == '`' || (input[i] == '$' && input[i + 1] == '(')) {
            int backtick = (input[i] == '`');
            i += backtick ? 1 : 2;
            size_t start = i;
            int depth = 1;

            while (input[i] && depth > 0) {
                if (!backtick && input[i] == '(')      depth++;
                else if (!backtick && input[i] == ')') depth--;
                else if (backtick && input[i] == '`')  break;
                i++;
            }

            char* cmd = safe_strndup(input + start, i - start);
            if (!cmd) continue;

            FILE* fp = popen(cmd, "r".ptr);
            free(cmd);
            if (!fp) continue;

            char[512] buf;
            while (fgets(buf.ptr, cast(int) buf.sizeof, fp)) {
                size_t len = strlen(buf.ptr);
                if (len && buf[len - 1] == '\n')
                    buf[len - 1] = 0;

                while (j + len >= out_len) {
                    out_len *= 2;
                    out_ = cast(char*) realloc(out_, out_len);
                    if (!out_) { pclose(fp); return cast(char*) calloc(1, 1); }
                }
                memcpy(out_ + j, buf.ptr, len);
                j += len;
            }
            pclose(fp);

            if (backtick)
                i++; // skip closing backtick
        } else {
            if (j + 1 >= out_len) {
                out_len *= 2;
                out_ = cast(char*) realloc(out_, out_len);
                if (!out_) return cast(char*) calloc(1, 1);
            }
            out_[j++] = input[i];
        }
    }

    out_[j] = '\0';
    return out_;
}

// ---------------------------------------------------------------------------
// Variable expansion  — handles $VAR, ${VAR}, and escape sequences
// ---------------------------------------------------------------------------
char* expand_variables(const(char)* input) nothrow @nogc {
    if (!input) return cast(char*) calloc(1, 1);

    char* out_ = cast(char*) malloc(BUFFER_SIZE);
    if (!out_) return cast(char*) calloc(1, 1);

    size_t out_len = BUFFER_SIZE;
    size_t j   = 0;
    size_t len = strlen(input);

    for (size_t i = 0; i < len; i++) {
        // Escape character
        if (input[i] == '\\' && input[i + 1]) {
            if (j + 1 >= out_len) {
                out_len *= 2;
                out_ = cast(char*) realloc(out_, out_len);
                if (!out_) return cast(char*) calloc(1, 1);
            }
            out_[j++] = input[++i];
            continue;
        }

        if (input[i] == '$') {
            i++;
            const(char)* val = null;

            if (input[i] == '{') {
                // ${VAR_NAME} form
                i++;
                size_t start = i;
                while (input[i] && input[i] != '}')
                    i++;

                if (input[i] == '}') {
                    char[MAX_VAR_NAME] name;
                    size_t nlen = i - start;
                    if (nlen < MAX_VAR_NAME) {
                        strncpy(name.ptr, input + start, nlen);
                        name[nlen] = '\0';
                        val = get_var(name.ptr);
                    }
                }
            } else if (isalpha(cast(ubyte) input[i]) || input[i] == '_') {
                // $VAR_NAME form
                size_t start = i;
                while (isalnum(cast(ubyte) input[i]) || input[i] == '_')
                    i++;

                char[MAX_VAR_NAME] name;
                size_t nlen = i - start;
                if (nlen < MAX_VAR_NAME) {
                    strncpy(name.ptr, input + start, nlen);
                    name[nlen] = '\0';
                    val = get_var(name.ptr);
                }
                i--;
            } else {
                // Bare $, not a variable reference
                if (j + 1 >= out_len) {
                    out_len *= 2;
                    out_ = cast(char*) realloc(out_, out_len);
                    if (!out_) return cast(char*) calloc(1, 1);
                }
                out_[j++] = '$';
                i--;
                continue;
            }

            if (val) {
                size_t val_len = strlen(val);
                while (j + val_len >= out_len) {
                    out_len *= 2;
                    out_ = cast(char*) realloc(out_, out_len);
                    if (!out_) return cast(char*) calloc(1, 1);
                }
                memcpy(out_ + j, val, val_len);
                j += val_len;
            }
        } else {
            if (j + 1 >= out_len) {
                out_len *= 2;
                out_ = cast(char*) realloc(out_, out_len);
                if (!out_) return cast(char*) calloc(1, 1);
            }
            out_[j++] = input[i];
        }
    }

    out_[j] = '\0';
    return out_;
}

// ---------------------------------------------------------------------------
// Tokenization — simple whitespace split, mirrors strtok-based C version
// ---------------------------------------------------------------------------
char** tokenize(const(char)* input) nothrow @nogc {
    if (!input || !*input) return cast(char**) calloc(1, (char*).sizeof);

    char* copy = strdup(input);
    if (!copy) return cast(char**) calloc(1, (char*).sizeof);

    char** tokens = cast(char**) malloc(MAX_TOKENS * (char*).sizeof);
    if (!tokens) {
        free(copy);
        return cast(char**) calloc(1, (char*).sizeof);
    }

    int   count = 0;
    char* ptr   = copy;

    char* tok;
    while ((tok = strtok(ptr, " \t".ptr)) !is null && count < MAX_TOKENS - 1) {
        tokens[count++] = strdup(tok);
        ptr = null;
    }
    tokens[count] = null;

    free(copy);
    return tokens;
}

void free_tokens(char** tokens) nothrow @nogc {
    if (!tokens) return;
    for (int i = 0; tokens[i]; i++)
        free(tokens[i]);
    free(tokens);
}

// ---------------------------------------------------------------------------
// Glob expansion
// ---------------------------------------------------------------------------
char** expand_globs(char** tokens) nothrow @nogc {
    if (!tokens || !tokens[0]) return tokens;

    char** result = cast(char**) malloc(MAX_TOKENS * (char*).sizeof);
    if (!result) return tokens;

    int    result_count = 0;
    glob_t globbuf;

    for (int i = 0; tokens[i] && result_count < MAX_TOKENS - 1; i++) {
        if (glob(tokens[i], GLOB_NOCHECK, null, &globbuf) == 0) {
            for (size_t j = 0; j < globbuf.gl_pathc && result_count < MAX_TOKENS - 1; j++)
                result[result_count++] = strdup(globbuf.gl_pathv[j]);
            globfree(&globbuf);
        } else {
            result[result_count++] = strdup(tokens[i]);
        }
    }
    result[result_count] = null;

    free_tokens(tokens);
    return result;
}

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------
int eval_condition(const(char)* cond) nothrow @nogc {
    if (!cond || !*cond) return 0;

    char* copy = strdup(cond);
    if (!copy) return 0;

    trim_string(copy);

    int result = 0;

    // Helper: split at two-char operator, returns pointer past op or null
    char* op2 = strstr(copy, "==".ptr);
    if (op2) {
        char* right = op2 + 2;
        *op2 = '\0';
        trim_string(copy);
        trim_string(right);
        result = strcmp(copy, right) == 0;
        goto done;
    }
    op2 = strstr(copy, "!=".ptr);
    if (op2) {
        char* right = op2 + 2;
        *op2 = '\0';
        trim_string(copy);
        trim_string(right);
        result = strcmp(copy, right) != 0;
        goto done;
    }
    op2 = strstr(copy, "<=".ptr);
    if (op2) {
        char* right = op2 + 2;
        *op2 = '\0';
        trim_string(copy);
        trim_string(right);
        result = atoi(copy) <= atoi(right);
        goto done;
    }
    op2 = strstr(copy, ">=".ptr);
    if (op2) {
        char* right = op2 + 2;
        *op2 = '\0';
        trim_string(copy);
        trim_string(right);
        result = atoi(copy) >= atoi(right);
        goto done;
    }
    {
        char* op1 = strstr(copy, "<".ptr);
        if (op1) {
            char* right = op1 + 1;
            *op1 = '\0';
            trim_string(copy);
            trim_string(right);
            result = atoi(copy) < atoi(right);
            goto done;
        }
    }
    {
        char* op1 = strstr(copy, ">".ptr);
        if (op1) {
            char* right = op1 + 1;
            *op1 = '\0';
            trim_string(copy);
            trim_string(right);
            result = atoi(copy) > atoi(right);
            goto done;
        }
    }
    // Non-empty string is truthy
    result = strlen(copy) > 0;

done:
    free(copy);
    return result;
}

// ---------------------------------------------------------------------------
// Arithmetic evaluation  — left-to-right, single-pass, +/-/*//%
// ---------------------------------------------------------------------------
long eval_arithmetic(const(char)* expr) nothrow @nogc {
    if (!expr || !*expr) return 0;

    char* expanded = expand_variables(expr);
    char* copy     = strdup(expanded);
    free(expanded);
    if (!copy) return 0;

    long   result  = 0;
    long   current = 0;
    char   op      = '+';
    char*  ptr     = copy;

    while (*ptr) {
        // Skip whitespace
        while (*ptr == ' ') ptr++;

        if (*ptr >= '0' && *ptr <= '9') {
            current = strtol(ptr, &ptr, 10);
        } else if (*ptr == '+' || *ptr == '-' || *ptr == '*' ||
                   *ptr == '/' || *ptr == '%') {
            // Apply the pending operation
            switch (op) {
                case '+': result += current; break;
                case '-': result -= current; break;
                case '*': result *= current; break;
                case '/': if (current != 0) result /= current; break;
                case '%': if (current != 0) result %= current; break;
                default:  break;
            }
            current = 0;
            op = *ptr;
            ptr++;
        } else {
            ptr++;
        }
    }

    // Apply the last operation
    switch (op) {
        case '+': result += current; break;
        case '-': result -= current; break;
        case '*': result *= current; break;
        case '/': if (current != 0) result /= current; break;
        case '%': if (current != 0) result %= current; break;
        default:  break;
    }

    free(copy);
    return result;
}

// ---------------------------------------------------------------------------
// Variable assignment detection & handling
// ---------------------------------------------------------------------------
int is_variable_assignment(const(char)* cmd) nothrow @nogc {
    if (!cmd || !*cmd || cmd[0] == '$') return 0;

    const(char)* eq = strchr(cmd, '=');
    if (!eq) return 0;

    for (const(char)* p = cmd; p < eq; p++)
        if (!isalnum(cast(ubyte)*p) && *p != '_')
            return 0;
    return 1;
}

void handle_assignment(const(char)* cmd) nothrow @nogc {
    if (!cmd || !*cmd) return;

    char* copy = strdup(cmd);
    if (!copy) return;

    char* eq = strchr(copy, '=');
    if (!eq) { free(copy); return; }

    *eq = '\0';
    char* name = copy;
    char* val  = eq + 1;

    // Arithmetic expansion:  VAR=$[expr]
    if (val[0] == '$' && val[1] == '[') {
        char* expr_start = val + 2;
        size_t slen = strlen(expr_start);
        if (slen > 0 && expr_start[slen - 1] == ']') {
            expr_start[slen - 1] = '\0';
            long res = eval_arithmetic(expr_start);
            char[64] buf;
            snprintf(buf.ptr, buf.sizeof, "%ld".ptr, res);
            set_var(name, buf.ptr);
        }
    } else {
        set_var(name, val);
    }

    free(copy);
}

// ---------------------------------------------------------------------------
// Command execution  — built-ins: cd, echo; everything else via fork+execvp
// ---------------------------------------------------------------------------
void run_command(char** args) nothrow @nogc {
    if (!args || !args[0]) return;

    if (strcmp(args[0], "cd".ptr) == 0) {
        const(char)* dir = args[1] ? args[1] : getenv("HOME".ptr);
        if (chdir(dir) != 0)
            perror("cd".ptr);
        return;
    }

    if (strcmp(args[0], "echo".ptr) == 0) {
        for (int i = 1; args[i]; i++) {
            printf("%s".ptr, args[i]);
            if (args[i + 1]) printf(" ".ptr);
        }
        printf("\n".ptr);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // child
        execvp(args[0], args);
        perror(args[0]);
        // Exit without touching D runtime (there is none, but be explicit)
        import core.sys.posix.unistd : _exit;
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    } else {
        perror("fork".ptr);
    }
}

// ---------------------------------------------------------------------------
// Dispatch a single line — handles while/if/repeat and plain commands
// ---------------------------------------------------------------------------

// Helper: run one command-line through the full pipeline
//   expand → assign-or-exec
void dispatch_line(const(char)* part) nothrow @nogc {
    if (!part || !*part) return;

    char* subbed   = substitute_commands(part);
    char* expanded = expand_variables(subbed);
    free(subbed);

    if (is_variable_assignment(expanded)) {
        handle_assignment(expanded);
    } else {
        char** tokens = tokenize(expanded);
        if (tokens && tokens[0]) {
            char** globbed = expand_globs(tokens);
            run_command(globbed);
            free_tokens(globbed);
        } else {
            free_tokens(tokens);
        }
    }
    free(expanded);
}

// Helper: execute a semicolon-separated command string
void exec_commands(char* commands_str) nothrow @nogc {
    char* cmd_copy = strdup(commands_str);
    char* part     = strtok(cmd_copy, ";".ptr);
    while (part) {
        trim_string(part);
        if (*part) dispatch_line(part);
        part = strtok(null, ";".ptr);
    }
    free(cmd_copy);
}

void execute_flow(const(char)* line) nothrow @nogc {
    if (!line || !*line) return;

    // Skip leading whitespace
    while (isspace(cast(ubyte)*line)) line++;
    if (!*line) return;

    // ── while (condition) commands ──────────────────────────────────────────
    if (strncmp(line, "while ".ptr, 6) == 0) {
        char* line_copy = strdup(line);
        if (!line_copy) return;

        char* p = line_copy + 6;
        while (isspace(cast(ubyte)*p)) p++;

        if (*p != '(') { free(line_copy); return; }
        p++;

        char* cond_start = p;
        char* cond_end   = strchr(p, ')');
        if (!cond_end) { free(line_copy); return; }

        *cond_end = '\0';
        char* cond_str      = strdup(cond_start);
        char* commands_start = cond_end + 1;
        while (isspace(cast(ubyte)*commands_start)) commands_start++;
        char* commands_str = strdup(commands_start);

        while (true) {
            char* expanded_cond = expand_variables(cond_str);
            if (!eval_condition(expanded_cond)) {
                free(expanded_cond);
                break;
            }
            free(expanded_cond);
            exec_commands(commands_str);
        }

        free(commands_str);
        free(cond_str);
        free(line_copy);
    }
    // ── if (condition) command ───────────────────────────────────────────────
    else if (strncmp(line, "if ".ptr, 3) == 0) {
        char* line_copy = strdup(line);
        if (!line_copy) return;

        char[256] cond;
        char[512] then_cmd;
        if (sscanf(line_copy, "if (%255[^)]) %511[^\n]".ptr,
                   cond.ptr, then_cmd.ptr) != 2) {
            free(line_copy);
            return;
        }

        char* expanded_cond = expand_variables(cond.ptr);
        int   ok            = eval_condition(expanded_cond);
        free(expanded_cond);

        if (ok) dispatch_line(then_cmd.ptr);

        free(line_copy);
    }
    // ── repeat N commands ────────────────────────────────────────────────────
    else if (strncmp(line, "repeat ".ptr, 7) == 0) {
        int   times;
        char[1024] commands;
        if (sscanf(line, "repeat %d %1023[^\n]".ptr,
                   &times, commands.ptr) == 2) {
            for (int i = 0; i < times; i++)
                exec_commands(commands.ptr);
        }
    }
    // ── regular command ──────────────────────────────────────────────────────
    else {
        dispatch_line(line);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
extern (C) int main() nothrow @nogc {
    printf("Asterix SHell, v0.9\n".ptr);

    atexit(&free_vars);

    while (true) {
        char* input = readline("asterix> ".ptr);
        if (!input) break;

        if (strcasecmp(input, "quit".ptr) == 0 ||
            strcasecmp(input, "exit".ptr) == 0) {
            free(input);
            break;
        }

        if (*input)
            add_history(input);

        execute_flow(input);
        free(input);
    }

    printf("Goodbye!\n".ptr);
    return 0;
}

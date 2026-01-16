# Asterix Shell

A lightweight, feature-rich shell implementation written in C.

## Features

- **Command Execution**: Run standard shell commands with argument parsing
- **Variable Management**: Set and get variables with `$VAR` or `${VAR}` expansion
- **Command Substitution**: Execute commands inline using backticks (`` `cmd` ``) or `$(cmd)` syntax
- **Arithmetic Expansion**: Evaluate mathematical expressions with `$[expression]` syntax supporting `+`, `-`, `*`, `/`, `%`
- **Glob Expansion**: Wildcard pattern matching with `*`, `?`, and character classes
- **Control Flow**:
  - `if (condition) command` and `if (condition) command; else other_command`
  - `while (condition) commands` for loops until condition becomes true
  - `repeat N commands` to execute commands N times
- **Input/Output Redirection**: 
  - `>` for output redirection (truncate)
  - `>>` for output redirection (append)
  - `<` for input redirection
  - `|` for piping between commands
- **Command History**: Interactive readline support with history navigation
- **Multiple Commands**: Execute multiple commands separated by `;`

## Building

### Linux

**Requirements:**
- GCC or Clang
- GNU Readline development library (`readline-devel` or `libreadline-dev`)
- OR Editline development library (`libedit-dev`) for a lighter alternative

**Compile with GNU Readline:**
```bash
gcc -o ash shell.c -lreadline
```

**Compile with Editline:**
```bash
gcc -DEDITLINE_ENABLED -o ash shell.c -leditline
```

Or with additional debugging:
```bash
gcc -g -Wall -o ash shell.c -lreadline
```

Or with Editline and debugging:
```bash
gcc -g -Wall -DEDITLINE_ENABLED -o ash shell.c -leditline
```

**Run:**
```bash
./ash
```

### Windows

**Requirements:**
- MinGW-w64 or similar GCC toolchain
- GNU Readline compiled for Windows (or use a compatible alternative)

**Compile with MinGW:**
```bash
gcc -o ash.exe shell.c -lreadline
```

**Alternative (without Readline):**
If readline is not available on Windows, you may need to modify the code to use Windows-specific console APIs or use a readline replacement compatible with Windows.

**Run:**
```bash
ash.exe
```

## Usage

Start the shell:
```bash
./ash
```

### Examples

**Variable assignment and expansion:**
```
asterix> x=42
asterix> echo $x
42
asterix> echo ${x}
42
```

**Arithmetic:**
```
asterix> result=$[10 + 5 * 2]
asterix> echo $result
20
```

**Command substitution:**
```
asterix> echo `date`
asterix> files=$(ls -la)
```

**Loops:**
```
asterix> while (x<5) echo $x; x=$[x+1]
asterix> repeat 3 echo "Hello"
```

**Conditional execution:**
```
asterix> if (x > 10) echo "Large"; else echo "Small"
```

**Piping and redirection:**
```
asterix> ls | grep shell
asterix> echo "test" > output.txt
asterix> cat < input.txt
```

**Exit:**
```
asterix> quit
asterix> exit
```

## Version

Asterix Shell v0.8

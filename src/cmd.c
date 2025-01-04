// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ 0
#define WRITE 1

/**
 * Internal change-directory command.
 */
static char *get_special_dir(const char *env_var, const char *error_message)
{

	if (getenv(env_var) == NULL)
	{
		printf("cd: %s\n", error_message);
	}

	return getenv(env_var);
}

static bool update_oldpwd()
{
	char cwd[1024];
	if (getcwd(cwd, sizeof(cwd)) == NULL)
	{
		perror("getcwd() error");
		return true;
	}

	if (setenv("OLDPWD", cwd, 1) == -1)
	{
		perror("setenv() error");
		return true;
	}

	return false;
}

static bool shell_cd(word_t *dir)
{
	char *dir_s = NULL;

	if (dir == NULL)
	{
		dir_s = get_special_dir("HOME", "HOME not set");
		if (dir_s == NULL)
			return true;
	}
	else
	{
		dir_s = get_word(dir);
		if (dir_s == NULL)
		{
			perror("get_word() error");
			return true;
		}
	}

	if (strcmp(dir_s, "-") == 0)
	{
		dir_s = get_special_dir("OLDPWD", "OLDPWD not set");
		if (dir_s == NULL)
			return true;
	}

	if (update_oldpwd())
		return true;

	/* Change current directory. */
	if (chdir(dir_s) == -1)
	{
		perror("cd");
		return true;
	}

	return false;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	exit(0);
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */

static int exec_builtin(simple_command_t *s)
{
	if (strcmp(s->verb->string, "exit") == 0 ||
		strcmp(s->verb->string, "quit") == 0)
		return shell_exit();
}

void cd_file_redirect(simple_command_t *s)
{
	if (s->out != NULL)
	{
		const char *filename = get_word(s->out);
		int flags = O_WRONLY | O_CREAT;
		mode_t mode = 0644;

		if (s->io_flags == 1)
		{
			flags |= O_APPEND;
		}
		else
		{
			flags |= O_TRUNC;
		}

		int fd = open(filename, flags, mode);

		if (fd == -1)
		{
			perror("open() error");
			return -1;
		}

		if (close(fd) == -1)
		{
			perror("close() error");
			return -1;
		}
	}
}
int check_verb_string(simple_command_t *s)
{
	if (!s->verb->string)
	{
		perror("get_word() error");
		return -1;
	}
	return 0;
}

int check_next_part(simple_command_t *s)
{
	if (!get_word(s->verb->next_part->next_part))
	{
		perror("get_word() error");
		return -1;
	}
	return 0;
}

int set_environment_variable(simple_command_t *s)
{
	int ret = setenv(s->verb->string, get_word(s->verb->next_part->next_part), 1);
	if (ret == -1)
	{
		perror("setenv() error");
		return -1;
	}
	return 0;
}

int handle_variable_assignment(simple_command_t *s)
{
	if (strcmp(s->verb->next_part->string, "=") == 0)
	{
		if (check_verb_string(s) == -1)
		{
			return -1;
		}

		if (check_next_part(s) == -1)
		{
			return -1;
		}

		if (set_environment_variable(s) == -1)
		{
			return -1;
		}

		return 0;
	}
	return -1;
}

int redirect_input(simple_command_t *s)
{
	if (s->in)
	{
		int fd = open(get_word(s->in), O_RDONLY);
		if (fd == -1)
		{
			perror("open() error");
			return -1;
		}

		if (dup2(fd, STDIN_FILENO) == -1)
		{
			perror("dup2() error");
			close(fd);
			return -1;
		}

		if (close(fd) == -1)
		{
			perror("close() error");
			return -1;
		}
	}
	return 0;
}

int open_and_dup(const char *path, int flags, int fd)
{
	int file_desc = open(path, flags, 0644);
	if (file_desc == -1)
	{
		perror("open() error");
		return -1;
	}

	if (dup2(file_desc, fd) == -1)
	{
		perror("dup2() error");
		close(file_desc);
		return -1;
	}

	if (close(file_desc) == -1)
	{
		perror("close() error");
		return -1;
	}

	return 0;
}

static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: If builtin command, execute the command. */
	exec_builtin(s);

	/* cd file redirects */
	if (strcmp(s->verb->string, "cd") == 0)
	{
		cd_file_redirect(s);
		return shell_cd(s->params);
	}

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part)
	{
		if (handle_variable_assignment(s) == 0)
		{
			return 0;
		}
	}

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	pid_t pid = fork();

	if (pid == 0)
	{
		/* Child process. */

		/* < Redirect input. */
		if (redirect_input(s) == -1)
		{
			return -1;
		}

		/* &> Redirect output and error to the same file. */
		if (s->out != NULL && s->err != NULL && strcmp(get_word(s->out), get_word(s->err)) == 0)
		{
			if (open_and_dup(get_word(s->out), O_WRONLY | O_CREAT | O_TRUNC, STDOUT_FILENO) == -1)
			{
				return -1;
			}

			if (dup2(STDOUT_FILENO, STDERR_FILENO) == -1)
			{
				perror("dup2() error");
				return -1;
			}
		}
		else
		{
			/* > , >> Redirect output. */
			if (s->out != NULL)
			{
				if (open_and_dup(get_word(s->out), O_WRONLY | O_CREAT | (s->io_flags == 1 ? O_APPEND : O_TRUNC), STDOUT_FILENO) == -1)
				{
					return -1;
				}
			}

			/* 2> , 2>> Redirect error. */
			if (s->err != NULL)
			{
				if (open_and_dup(get_word(s->err), O_WRONLY | O_CREAT | (s->io_flags == 2 ? O_APPEND : O_TRUNC), STDERR_FILENO) == -1)
				{
					return -1;
				}
			}
		}

		/* Execute command. */
		int size;
		char **argv = get_argv(s, &size);

		int ret = execvp(argv[0], argv);

		if (ret == -1)
		{ /* Command not found. */
			printf("Execution failed for '%s'\n", argv[0]);
			exit(-1);
		}
	}

	/* Parent process. */
	int status;

	if (waitpid(pid, &status, 0) == -1)
	{
		perror("waitpid() error");
		return -1;
	}

	return status; /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
							command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	pid_t pid1 = fork();

	if (pid1 == 0)
	{
		/* Child process. */
		int ret = parse_command(cmd1, level + 1, father);
		exit(ret);
	}

	pid_t pid2 = fork();

	if (pid2 == 0)
	{
		/* Child process. */
		int ret = parse_command(cmd2, level + 1, father);
		exit(ret);
	}

	/* Parent process. */

	/* Wait for children. */
	int status;

	if (waitpid(pid1, &status, 0) == -1)
	{
		perror("waitpid() error");
		return true;
	}

	if (waitpid(pid2, &status, 0) == -1)
	{
		perror("waitpid() error");
		return true;
	}

	return status; /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */

int handle_child_process(int pipefd[], int close_fd, int dup_fd, int std_fd, command_t *cmd, int level, command_t *father)
{
	if (close(pipefd[close_fd]) == -1)
	{
		perror("close() error");
		return true;
	}

	if (dup2(pipefd[dup_fd], std_fd) == -1)
	{
		perror("dup2() error");
		return true;
	}

	int ret = parse_command(cmd, level, father);
	exit(ret);
}

static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
						command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	int pipefd[2];

	if (pipe(pipefd) == -1)
	{
		perror("pipe() error");
		return true;
	}

	pid_t pid1 = fork();

	if (pid1 == 0)
	{
		/* Child process. */
		handle_child_process(pipefd, READ, WRITE, STDOUT_FILENO, cmd1, level, father);
	}

	pid_t pid2 = fork();

	if (pid2 == 0)
	{
		/* Child process. */
		handle_child_process(pipefd, WRITE, READ, STDIN_FILENO, cmd2, level, father);
	}

	/* Parent process. */

	/* Close read end of pipe. */
	if (close(pipefd[READ]) == -1)
	{
		perror("close() error");
		return true;
	}

	/* Close write end of pipe. */
	if (close(pipefd[WRITE]) == -1)
	{
		perror("close() error");
		return true;
	}

	/* Wait for children. */
	int status;

	if (waitpid(pid1, &status, 0) == -1)
	{
		perror("waitpid() error");
		return true;
	}

	if (waitpid(pid2, &status, 0) == -1)
	{
		perror("waitpid() error");
		return true;
	}

	return status; /* TODO: Replace with actual exit status. */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{

	if (c->op == OP_NONE)
	{
		/* TODO: Execute a simple command. */
		int ret = parse_simple(c->scmd, level, father);

		return ret; /* TODO: Replace with actual exit code of command. */
	}

	int ret;

	if (c->op == OP_SEQUENTIAL)
	{
		/* TODO: Execute the commands one after the other. */

		/* Execute first command. */
		ret = parse_command(c->cmd1, level, father);
		if (ret == -1)
		{
			fprintf(stderr, "%s error", __func__);
			return -1;
		}

		/* Execute second command. */
		ret = parse_command(c->cmd2, level, father);
		if (ret == -1)
		{
			fprintf(stderr, "%s error", __func__);
			return -1;
		}
	}
	else if (c->op == OP_PARALLEL)
	{
		/* TODO: Execute the commands simultaneously. */
		ret = run_in_parallel(c->cmd1, c->cmd2, level, father);
		if (ret == true)
		{
			perror("run_in_parallel() error");
			return -1;
		}
	}
	else if (c->op == OP_CONDITIONAL_NZERO)
	{
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */

		/* Execute first command. */
		ret = parse_command(c->cmd1, level, father);
		if (ret == -1)
		{
			fprintf(stderr, "%s error", __func__);
			return -1;
		}

		/* Execute second command. */
		if (ret != 0)
		{
			ret = parse_command(c->cmd2, level, father);
			if (ret == -1)
			{
				fprintf(stderr, "%s error", __func__);
				return -1;
			}
		}
	}
	else if (c->op == OP_CONDITIONAL_ZERO)
	{
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */

		/* Execute first command. */
		ret = parse_command(c->cmd1, level, father);
		if (ret == -1)
		{
			fprintf(stderr, "%s error", __func__);
			return -1;
		}

		/* Execute second command. */
		if (ret == 0)
		{
			ret = parse_command(c->cmd2, level, father);
			if (ret == -1)
			{
				fprintf(stderr, "%s error", __func__);
				return -1;
			}
		}
	}
	else if (c->op == OP_PIPE)
	{
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */

		/* Execute commands on pipe. */
		ret = run_on_pipe(c->cmd1, c->cmd2, level, father);
		if (ret == true)
		{
			perror("run_on_pipe() error");
			return -1;
		}
	}
	else
	{
		return SHELL_EXIT;
	}

	return ret; /* TODO: Replace with actual exit code of command. */
}
#ifndef PARSER_H
#define PARSER_H

int parse_config_line(const char *line, char *key, char *value);
char *trim(char *s);
int split_fields(char *line, char **fields, int max_fields, int *count);
void log_event(const char *tag, const char *detail);
int find_matching_paren(const char *s, int open_pos);

#endif /* PARSER_H */

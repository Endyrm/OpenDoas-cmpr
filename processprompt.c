char *replaceall(char *orig, char *rep, char *with) {
    char *result;
    char *ins = orig;
    char *tmp;
    int len_rep = strlen(rep);
    int len_with = strlen(with);
    int len_front;
    int count;

    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }
    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);
    if (!result)
        return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

char *
processprompt(char *str, char *username, char *hostname) {
	char *escapesequence = "\x1b";
	str = replaceall(str, "\\033", escapesequence);
	str = replaceall(str, "\\e", escapesequence);
	str = replaceall(str, "\\x1b", escapesequence);

	str = replaceall(str, "\%u", username);
	str = replaceall(str, "\%h", hostname);

	return replaceall(str, "%", "%%");
}

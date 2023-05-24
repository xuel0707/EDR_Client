#ifndef __QT_LANGUAGE_H_
#define __QT_LANGUAGE_H_

#include <stdio.h>
#include <string.h>

int lang = 0; //0 Chinese, 1 Englist
#define LANGFILE "/opt/snipercli/.language"

/* Chinese return 0; Englist 1 */
static int get_language(void)
{
	FILE *fp = NULL;
	char buf[256] = {0};

	fp = fopen(LANGFILE, "r");
	if (fp) {
		if (fgets(buf, 256, fp) == NULL) {
			fclose(fp);
			return 0;
		}
		fclose(fp);

		if (strcasestr(buf, "English")) {
			return 1;
		}
	}
	return 0;
}

void remember_language(const char *langstr)
{
	FILE *fp = NULL;

	fp = fopen(LANGFILE, "w");
	if (fp) {
		fputs(langstr, fp);
		fflush(fp);
		fclose(fp);
	}
}

#endif

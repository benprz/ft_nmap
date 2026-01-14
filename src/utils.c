#include <stddef.h>
#include <ctype.h>

char	*trim_whitespaces(char *str)
{
	size_t	i = 0;
	while (isspace(str[i]))
		i++;
	str += i;
	if (!str[0])
		return (str);
	i = 0;
	while (str[i] && !isspace(str[i]))
		i++;
	str[i] = 0;
	return (str);
}

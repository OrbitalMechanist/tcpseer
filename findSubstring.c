/*Returns the position, starting at 1 like humans, of substring
 within searchTarget, or 0 if it is not present. Goes well with
 if statements.
*/
int findSubstring(char *searchTarget, char *substring)
{
    int position = 0;
    int substringLength = strlen(substring);
    do
    {
        position++;
        int matchingChars = 0;
        while (*searchTarget == *substring)
        {
            searchTarget++;
            substring++;
            matchingChars++;
            if (matchingChars == substringLength)
            {
                return position;
            }
        }
        searchTarget -= matchingChars;
        substring -= matchingChars;
    } while (*searchTarget++);
    return 0;
}

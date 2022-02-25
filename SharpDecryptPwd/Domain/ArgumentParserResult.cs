using System.Collections.Generic;

namespace SharpDecryptPwd.Domain
{
    public class ArgumentParserResult
    {
        public bool ParsedOk { get; }
        public ArgumentParserContent Arguments { get; }

        private ArgumentParserResult(bool parsedOk, Dictionary<string, string> arguments)
        {
            ParsedOk = parsedOk;
            Arguments = new ArgumentParserContent(arguments);
        }

        public static ArgumentParserResult Success(Dictionary<string, string> arguments)
            => new ArgumentParserResult(true, arguments);

        public static ArgumentParserResult Failure()
            => new ArgumentParserResult(false, null);
    }
}

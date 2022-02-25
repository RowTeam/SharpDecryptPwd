using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpDecryptPwd.Domain
{
    public class ArgumentParserContent
    {
        public string module { get; }
        public string argument { get; }
        public string path { get; }
        public string destination { get; }
        public string user { get; }
        public string sid { get; }


        public ArgumentParserContent(Dictionary<string, string> arguments)
        {
            module = ArgumentParser(arguments, "/module");
            argument = ArgumentParser(arguments, "/argument");
            destination = ArgumentParser(arguments, "/destination");
            user = ArgumentParser(arguments, "/user");
            sid = ArgumentParser(arguments, "/sid");
            path = ArgumentParser(arguments, "/path");
        }

        private string ArgumentParser(Dictionary<string, string> arguments, string flag)
        {
            if (arguments.ContainsKey(flag) && !string.IsNullOrEmpty(arguments[flag]))
            {
                return arguments[flag];
            }
            return null;
        }
    }
}

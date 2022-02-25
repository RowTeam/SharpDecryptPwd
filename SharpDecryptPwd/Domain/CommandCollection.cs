using System;
using SharpDecryptPwd.Commands;
using System.Collections.Generic;

namespace SharpDecryptPwd.Domain
{
    public class CommandCollection
    {
        public bool ExecuteCommand(string commandName, ArgumentParserContent arguments, Dictionary<string, Func<ICommand>> _availableCommands)
        {
            bool commandWasFound;
            if (string.IsNullOrEmpty(commandName) || _availableCommands.ContainsKey(commandName) == false)
                commandWasFound = false;
            else
            {
                // 創建命令對象
                var command = _availableCommands[commandName].Invoke();

                // 代入命令行中的參數
                command.DecryptPwd(arguments);

                commandWasFound = true;
            }
            return commandWasFound;
        }
    }
}

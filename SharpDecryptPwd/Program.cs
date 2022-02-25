using System;
using System.Reflection;
using SharpDecryptPwd.Domain;
using SharpDecryptPwd.Helpers;
using SharpDecryptPwd.Commands;
using System.Collections.Generic;

namespace SharpDecryptPwd
{
    class Program
    {
        static string FileName = Assembly.GetExecutingAssembly().GetName().Name;

        /// <summary>
        /// 添加新方法
        /// </summary>
        private static Dictionary<string, Func<ICommand>> AddDictionary()
        {
            Dictionary<string, Func<ICommand>> _availableCommands = new Dictionary<string, Func<ICommand>>();
            _availableCommands.Add(Chrome.CommandName, () => new Chrome());
            _availableCommands.Add(FileZilla.CommandName, () => new FileZilla());
            _availableCommands.Add(Foxmail.CommandName, () => new Foxmail());
            _availableCommands.Add(Navicat.CommandName, () => new Navicat());
            _availableCommands.Add(RDCMan.CommandName, () => new RDCMan());
            _availableCommands.Add(Xmanager.CommandName, () => new Xmanager());
            _availableCommands.Add(TortoiseSVN.CommandName, () => new TortoiseSVN());
            _availableCommands.Add(WinSCP.CommandName, () => new WinSCP());
            _availableCommands.Add(Sunlogin.CommandName, () => new Sunlogin());

            return _availableCommands;
        }

        /// <summary>
        /// 執行方法
        /// </summary>
        private static void MainExecute(string commandName, ArgumentParserContent parsedArgs)
        {
            Info.ShowLogo();

            try
            {
                Writer.Line($"------------------ {commandName} ------------------\r\n");
                var commandFound = new CommandCollection().ExecuteCommand(commandName, parsedArgs, AddDictionary());

                // 如果未找到方法，則輸出使用方法
                if (commandFound == false)
                    Info.ShowUsage();
            }
            catch (Exception e)
            {
                Console.WriteLine($"\r\n[!] Unhandled {FileName} exception:\r\n");
                Console.WriteLine(e.Message);
            }
        }

        static void Main(string[] args)
        {
            // 尝试解析命令行参数
            var parsed = ArgumentParser.Parse(args);
            if (parsed.ParsedOk == false)
            {
                Info.ShowLogo();
                Info.ShowUsage();
                return;
            }

            var commandName = args.Length != 0 ? args[0] : "";
            MainExecute(commandName.ToLower(), parsed.Arguments);
        }
    }
}

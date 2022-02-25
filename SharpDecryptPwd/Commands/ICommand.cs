namespace SharpDecryptPwd.Commands
{
    public interface ICommand
    {
        void DecryptPwd(Domain.ArgumentParserContent arguments);
    }
}

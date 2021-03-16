package npDev.telegramBot.cnSecurity.handler;


import npDev.telegramBot.cnSecurity.Bot;
import npDev.telegramBot.shell.DocumentShell;
import npDev.telegramBot.shell.MessageShell;

public class FileHandler extends LinkHandler {
    private final DocumentShell document;

    public FileHandler(Bot conf, MessageShell message) {
        super(conf, message);
//		document=message.document();
        document = null;//TODO
    }

    private void doDelete() {
    }

    public void doCheck() {
        // TODO 先检查安全性
        if (message.hasUrl()) {
            super.doCheck();
        }
    }
}
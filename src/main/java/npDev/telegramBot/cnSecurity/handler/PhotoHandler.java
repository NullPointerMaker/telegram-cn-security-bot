package npDev.telegramBot.cnSecurity.handler;

import npDev.telegramBot.cnSecurity.Bot;
import npDev.telegramBot.shell.MessageShell;

public class PhotoHandler extends FileHandler {
    public PhotoHandler(Bot conf, MessageShell message) {
        super(conf, message);
//		document=message.document();
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
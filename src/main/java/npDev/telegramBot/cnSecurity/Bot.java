package npDev.telegramBot.cnSecurity;

import com.pengrad.telegrambot.UpdatesListener;
import com.pengrad.telegrambot.model.Update;
import npDev.telegramBot.Instance;
import npDev.telegramBot.cnSecurity.handler.DeleteHandler;
import npDev.telegramBot.cnSecurity.handler.FileHandler;
import npDev.telegramBot.cnSecurity.handler.LinkHandler;
import npDev.telegramBot.shell.MessageShell;

import java.util.List;
import java.util.logging.Logger;

public class Bot extends Instance {
    	public static final Logger LOG = Logger.getGlobal();
    public Bot(String fileName) {
        super(fileName);
    }

    public static void main(String[] args) {
        System.setProperty("java.net.useSystemProxies", "true");
        new Bot("telegram-cn-security-bot.conf");
    }

    @Override
    public int process(List<Update> updates) {
        try {
            for (Update update : updates) {
                MessageShell message = new MessageShell(update.message());
				if(getUser().equals(message.getForwardFrom())) {//转自自己
					continue;//不解析
				}
                if (message.hasCommand(DeleteHandler.COMMAND, getUser().getAtUsername())) {//删除指令
                    new DeleteHandler(this, message).doDelete();
                    continue;
                }
                if (message.hasDocument()) {//新消息含有文件
                    new FileHandler(this, message).doCheck();
                    continue;
                }
                if (message.isNull()) {//不是新消息
                    message = new MessageShell(update.editedMessage());
                }
                if (message.hasUrl()) {//消息含有链接
                    new LinkHandler(this, message).doCheck();
                    //continue;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return UpdatesListener.CONFIRMED_UPDATES_NONE;
        }
        return UpdatesListener.CONFIRMED_UPDATES_ALL;
    }

    public Integer getTorPort() {
        return getInteger("tor_port", null);
    }

    public Integer getTipSeconds() {
        return getInteger("tip_seconds", 9);
    }
}

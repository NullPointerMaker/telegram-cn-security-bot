package npDev.telegramBot.cnSecurity.handler;


import npDev.telegramBot.cnSecurity.Bot;
import npDev.telegramBot.shell.MessageShell;

public class DeleteHandler {
    public static final String COMMAND = "(del(ete)?|report)";
    private final Bot bot;
    private final MessageShell command, target;

    //	private final UserShell cleaner;
    public DeleteHandler(Bot bot, MessageShell message) {
        this.bot = bot;
        this.command = message;
//		this.cleaner = command.from();
        this.target = command.getReplyToMessage();
    }

    public void doDelete() {
        if (!command.getChat().isGroupChat()) {//不是群聊
            return;
        }//是群聊
        if (target.isNull()) {//没有目标
            doReplyToCommand("请用 `/delete` *回复*想要删除的消息。");
            command.doDelete(bot);
            return;
        }//有目标
        doDelete(target);
    }

    /**
     * 递归删除（但似乎 API 不支持）
     *
     * @param target 想要删除的目标消息
     */
    private void doDelete(MessageShell target) {
        if (target.isNull()) {//没有目标
            return;
        }//有目标
        if (!bot.getUser().equals(target.getFrom())) {//想删除的不是自己
            return;
        }
        MessageShell targetReplyTo = target.getReplyToMessage();//
        if (!targetReplyTo.isNull()) {//目标有回复对象
            doDelete(targetReplyTo);
        } else if (target.hasText() && !target.hasURL()) {//目标没有回复对象且是不含链接的纯文本
            target.doDelete(bot);
            command.doDelete(bot);
            return;
        }//目标没有回复对象且含链接或媒体
        //TODO 判断是图集，查数据库，延时提示，删除全部，删除数据库
        String text = String.format("将应 %s 的请求撤回该消息。", command.getFromMarkdown());
        MessageShell reply = target.doReply(bot, text, false, null);
        reply.doDeleteAfter(bot, bot.getTipSeconds());
        target.doDeleteAfter(bot, bot.getTipSeconds());
        command.doDelete(bot);
    }

    private void doReplyToCommand(@SuppressWarnings("SameParameterValue") String text) {
        MessageShell reply = command.doReply(bot, text, true, null);
        if (!reply.isNull()) {
            reply.doDeleteAfter(bot, bot.getTipSeconds());
        }
    }
}
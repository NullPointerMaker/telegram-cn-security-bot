package npDev.telegramBot.cnSecurity.handler;

import npDev.telegramBot.Utilities;
import npDev.telegramBot.cnSecurity.Bot;
import npDev.telegramBot.shell.MessageShell;
import okhttp3.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Arrays;
import java.util.HashSet;

public class LinkHandler {
    private static final String TIP_WARN = "为防 IP 等个人信息泄露，建议访问者通过代理软件在浏览器 InPrivate 隐私模式下查看，同时不要登录实名账号。",//public
            TIP_UNSAFE_PUBLIC = "建议下次分享前先私发我局进行检测。",//public
            TIP_OTHER = "链接安全性未知或不含中文信息。已收集分析。",
            TIP_SAFE = "链接不含追踪标记，未泄露分享者的个人信息。",
            TIP_UNSAFE = "链接含有追踪标记，会泄露分享者的个人信息！",
            TIP_UNSAFE_WARN = "链接含有追踪标记，会泄露分享者和访问者的个人信息！",//public
            TIP_REPOST = "已尝试脱敏，下为处理后消息。",
            TIP_REPOST_PUBLIC = "已尝试脱敏，下为处理后消息。回复 `/delete` 可删除。",//public
            TIP_ARCHIVE = "尝试脱敏失败。\n图文内容建议用 @CNArchiveBot 转录为 Telegraph 后分享。\n多媒体和文件建议下载后上传到 Telegram。",
    //            TIP_CLOUD = "网盘文件与账号相关联，会泄露分享者和访问者的个人信息。\n建议 2GB 内文件直接发送。超出可采用分割压缩的办法。如何分割压缩请自行搜索。",
    REGEX_PREFIX = "(?i)https?://([\\w-]+\\.)*(", REGEX_SUFFIX = "(:\\d+)?)([/#?]\\S*)?",
            REGEX_PASS = "tg://\\S*|" +
                    "\\S+@\\S+\\.\\w+|" + REGEX_PREFIX//忽略
                    + "t(\\.me|e\\.?legra(\\.ph|m\\.org))"//telegram
                    + "|127\\.0\\.0\\.1|\\[::1]|localhost"//本地
                    + "|onion"//tor网络
                    + "|searx.be"//无追踪搜索引擎
                    + REGEX_SUFFIX, REGEX_SAFE = REGEX_PREFIX//访问安全
            + "gov"//美国政府
            + "|4chan\\.org"//
            + "|amnesty\\.org"//国际特赦
            + "|apkpure\\.com"//
            + "|appledaily\\.com"//苹果日报
            +"|archive\\.org"//互联网档案
            + "|bbc\\.com"//
            + "|bloomberg(china)?\\.com"//彭博社
            + "|bolshevik\\.info"//IDOM
            + "|chinaworker\\.info"//中国劳工论坛
            + "|chinadigitaltimes\\.net"//中国数字时代
            + "|discord\\.com"//
            + "|dw\\.com"//德国之声
            + "|facebook\\.com"
            + "|fandom\\.com"//
            + "|ft(chinese)?\\.com"//金融时报
            + "|github\\.com"//
            + "|(docs|drive|support)\\.google\\.com"//
            + "|greasyfork\\.org"//浏览器脚本
            + "|humblebundle\\.com"//游戏促销
            + "|inmediahk\\.net"//香港独立媒体
            + "|ipfs\\.io"//
            + "|iyouport\\.org"//
            + "|lih(kg\\.com|\\.kg)"//连登
            + "|mega\\.nz"//网盘
            + "|marxist\\.tw"//IMT台湾
            + "|marxists\\.org"//马克思主义文库
            + "|matters\\.news"//区块链社交网站
            + "|medium\\.com"//
            + "|microsoft\\.com"//微软
            + "|minghui\\.org"//明慧网
            + "|mozilla\\.org"//firefox
            + "|nswp\\.org"//世界性工作者权益组织
            + "|nhk\\.or\\.jp"//日本NHK电视台
            + "|ntdtv\\.com"//新唐人
            + "|nytimes\\.com"//纽约时报
            + "|patreon\\.com"//付费阅读平台
            + "|pixiv\\.net"//p站
            + "|ptt\\.cc"//批踢踢
            + "|redants\\.sg"//beritaharian旗下红蚂蚁
            + "|reuters\\.com"//路透社
            + "|rthk\\.hk"//香港电台
            + "|safeguarddefenders\\.com"//保护卫士
            + "|steampowered\\.com"//steam
            + "|sleazyfork\\.org"//浏览器脚本
            + "|theguardian\\.com"//卫报
            + "|theinitium\\.com"//端传媒
            + "|vox\\.com"//福克斯
            + "|wenxuecity\\.com"//文学城
            + "|wikia\\.org"//
            + "|wsj\\.com"//华尔街日报
            + REGEX_SUFFIX, REGEX_SAFE_WARN = REGEX_PREFIX//访问不安全
            + "appinn\\.com"//小众
            + "|baike\\.baidu\\.com"//百度百科
            + "|biliob\\.com"//观测站
            + "|caixin\\.com"//财新
            + "|cbndata\\.com"//
            + "|chouti\\.com"//抽屉
            + "|cnbeta\\.com"//
            + "|coolapk\\.com"//酷安
            + "|deshangbao\\.com"//德商宝
            + "|douban\\.com"//豆瓣
            + "|eastday\\.com"//东方
            + "|expreview\\.com"//超能评测
            + "|(51gonghao|8values)\\.github\\.io"//github.io
            + "|huawei\\.com"//华为
            + "|iqiyi\\.com"//爱奇艺
            + "|ithome\\.com"//it之家
            + "|jandan\\.net"//煎蛋
            + "|landiannews\\.com"//蓝点
            + "|leiphone\\.com"//雷锋
            + "|(new|mp\\.weixin)\\.qq\\.com(/s/\\S+)?"//腾讯新闻微信安全
            + "|redchinacn\\.net"//红色中国网
            + "|saraba1st\\.com"//s1
            + "|sohu\\.com"//搜狐
            + "|sspai\\.com"//少数派
            + "|taobao\\.com"//淘宝
            + "|tuhu\\.org"//途虎
            + "|unionpayintl\\.com"//银联
            + "|v2ex\\.com"//
            + "|xinhuanet\\.com"//新华网
            + "|yicai\\.com"//第一财经
            + "|zhihu\\.com"//知乎
            + REGEX_SUFFIX, REGEX_ARCHIVE = REGEX_PREFIX//需要存档无法脱敏
            + "360kuai\\.com"//360快新闻
            + "|baidu\\.com/video"//百度视频
            + "|pan\\.baidu\\.com"//百度云百度网盘
            + "|chouti\\.com/pic/show\\?\\S+"//抽屉分享
            + "|mp\\.weixin\\.qq\\.com/s\\?\\S+"//微信
            + "|partners\\.sina\\.cn"//新浪头条
            + "|share\\.weiyun\\.com"//微云网盘
            + REGEX_SUFFIX
//        , REGEX_CLOUD = REGEX_PREFIX//网盘
//            + "pan\\.baidu\\.com"//百度云百度网盘
//            + "|share\\.weiyun\\.com"//微云网盘
//            + REGEX_SUFFIX
            ;
    protected final MessageShell message;
    private final OkHttpClient client;
    private final boolean isPrivate;
    //        private final boolean isForwardFromRepost;
    private final Bot bot;
    private Level level = Level.SAFE;

    public LinkHandler(Bot bot, MessageShell message) {
        this.bot = bot;
        this.message = message;
        isPrivate = message.getChat().isPrivate();
//        isForwardFromRepost = bot.getUser().equals(message.getForwardFrom());
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        Integer torPort = bot.getTorPort();
        if (torPort != null && torPort != 0) {
            InetSocketAddress address = new InetSocketAddress("127.0.0.1", bot.getTorPort());
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, address);//通过tor连接
            builder.proxy(proxy);
        }
        //TODO 忽略证书校验？
        client = builder.build();
    }

    public void doCheck() {
        String[] markdownAndURLs = message.toMarkdownAndURLs();
        if (markdownAndURLs == null) {
            return;
        }
        message.getChat().doTyping(bot);
        String[] urls = Arrays.copyOfRange(markdownAndURLs, 1, markdownAndURLs.length);
        for (int i = 0; i < urls.length; i++) {
            boolean isMarkdown = urls[i].contains("\\");
            urls[i] = urls[i].replace("\\", "");
            urls[i] = checkURL(urls[i], false);
            if (urls[i] != null && isMarkdown) {
                urls[i] = Utilities.completeToMarkdown(urls[i]);
            }
        }
        switch (level) {
//            case CLOUD:
//                if (doReply(TIP_CLOUD, TIP_UNSAFE_PUBLIC)) {
//                    doDelete();
//                }
//                break;
            case ARCHIVE:
                if (doReply(TIP_UNSAFE_WARN, TIP_ARCHIVE, TIP_UNSAFE_PUBLIC)) {
                    doDelete();
                }
                break;
            case REPOST_WARN:
                if (doReply(TIP_UNSAFE_WARN, TIP_UNSAFE_PUBLIC, TIP_REPOST_PUBLIC)) {
                    doRepost(markdownAndURLs[0], urls, true);
                    doDelete();
                }
                break;
            case REPOST:
                if (doReply(TIP_UNSAFE, TIP_UNSAFE_PUBLIC, TIP_REPOST_PUBLIC)) {
                    doRepost(markdownAndURLs[0], urls, false);
                    doDelete();
                }
                break;
            case OTHER_WARN:
                doReply(TIP_OTHER, TIP_WARN);
                break;
            case SAFE_WARN:
                doReply(TIP_SAFE, TIP_WARN);
                break;
            case SAFE:
                doReply(TIP_SAFE);
            case PASS:
            default:
                break;
        }
    }

    private void doRepost(String markdown, Object[] urls, boolean isWarn) {
        StringBuilder sb = new StringBuilder();
        if (!isPrivate) {
            String from = message.getFromMarkdown();
            if (from != null) {
                sb.append(from);
            }
        }
// String forwardFromMarkdown=message.getForwardFromMessageMarkdown();
// if(forwardFromMarkdown==null) {//转发来自用户
// 	UserShell forwardFrom=message.forwardFrom();
// 	if(forwardFrom.isNull()) {//用户隐藏
// 		forwardFromMarkdown=message.forwardSenderName();
// 		if(forwardFromMarkdown!=null) {forwardFromMarkdown="`"+forwardFromMarkdown+"`";}
// 	}else {//用户未隐藏
// 		forwardFromMarkdown=message.forwardFrom().getMentionMarkdown();
// 	}
// }
        String forwardFromMarkdown = message.getForwardFromMarkdown();
        if (forwardFromMarkdown != null) {
            sb.append(" 转自 ").append(forwardFromMarkdown);
        }
        if (sb.length() > 0) {
            sb.append("\n");
        }
        sb.append(String.format(markdown, urls));
        //TODO 如果是caption，重新上传
        //TODO 兼容图集，用bdb记录图集，用线程删除图集，线程内如果异常就过段时间再删。
        if (!isPrivate && isWarn) {
            sb.append("\n_").append(TIP_WARN).append("_");
        }
        message.doRepost(bot, sb.toString().trim());
    }

    private boolean doReply(String... tips) {
        StringBuilder sb = new StringBuilder();
        for (String tip : tips) {
            switch (tip) {
                case TIP_REPOST_PUBLIC:
                    tip = isPrivate ? TIP_REPOST : tip;
                    break;
                case TIP_UNSAFE_WARN:
                    tip = isPrivate ? TIP_UNSAFE : tip;
                    break;
                case TIP_SAFE:
                    tip = isPrivate ? tip : null;
                    break;
                case TIP_WARN:
                case TIP_UNSAFE_PUBLIC:
                    tip = isPrivate ? null : tip;
                    break;
                default:
                    break;
            }
            if (tip != null) {
                sb.append(tip).append("\n");
            }
        }
        if (sb.length() > 0) {
            return !message.doReply(bot, sb.toString().trim(), true, null).isNull();
        }
        return false;
    }

    private void doDelete() {
        if (!isPrivate) {
            message.doDelete(bot);
        }
    }

    /**
     * @param url      原链接
     * @param isTarget 是否已经解析
     * @return 无风险的链接或无链接
     */
    private String checkURL(String url, boolean isTarget) {
//		if(!url.toLowerCase().startsWith("http")) {//ftp
//			setLevel(Level.OTHER_WARN);
//			return url;
//		}
//        if (url.matches(REGEX_CLOUD)) {
//            setLevel(Level.CLOUD);
//            return null;
//        }
        if (url.matches(REGEX_ARCHIVE)) {// 无法脱敏
            setLevel(Level.ARCHIVE);// 无法脱敏
            return null;
        }
        if (url.matches(REGEX_SAFE_WARN)) {
            return trimURL(url, true);
        }
        if (isTarget && url.matches(REGEX_PREFIX + "cn" + REGEX_SUFFIX)) {
            return trimURL(url, true);
        }
        if (url.matches(REGEX_PREFIX + "gov\\.cn" + REGEX_SUFFIX)) {//政府网站
            return trimURL(url, true, "code");
        }
        if (url.matches(REGEX_PREFIX + "music\\.163\\.com" + REGEX_SUFFIX)) {//网易云音乐
            return trimURL(url, true, "id");
        }
        if (url.matches(REGEX_PREFIX + "open\\.163\\.com" + REGEX_SUFFIX)) {//网易公开课
            return trimURL(url, true, "plid","pid","mid");
        }
//		if(url.matches(REGEX_PREFIX+"baidu\\.com/video"+REGEX_SUFFIX)) {//百度视频
//			return trimURL(url,true,"cambrian_id","word","atn","nid");
//		}
        if (url.matches(REGEX_PREFIX + "baijiahao\\.baidu\\.com" + REGEX_SUFFIX)) {//百度百家号
            return trimURL(url, true, "id");
        }
        if (url.matches(REGEX_PREFIX + "b(ilibili\\.com|23\\.tv/[ab]v\\S+)" + REGEX_SUFFIX)) {//bilibili
            return trimURL(url, true, "p");
        }
        if (url.matches(REGEX_PREFIX + "ngabbs\\.com" + REGEX_SUFFIX)) {
            return trimURL(url, true, "tid");
        }
        if (url.matches(REGEX_PREFIX + "qzone\\.qq\\.com" + REGEX_SUFFIX)) {
            return trimURL(url, true, "res_uin", "cellid", "appid");
        }
        if (url.matches(REGEX_PREFIX + "solidot\\.org" + REGEX_SUFFIX)) {
            return trimURL(url, true, "sid", "issue");
        }
        if (url.matches(REGEX_PREFIX + "weibo\\.(com|cn)" + REGEX_SUFFIX)) {//微博
            return trimURL(url, true, "containerid");
        }
        if (url.matches(REGEX_SAFE)) {
            return trimURL(url, false);
        }
        if (url.matches(REGEX_PREFIX + "podcast\\.apple\\.com" + REGEX_SUFFIX)) {//苹果
            return trimURL(url, false, "i");
        }
        if (url.matches(REGEX_PREFIX + "blogspot\\.com" + REGEX_SUFFIX)) {
            return trimURL(url, false, "m");
        }
        if (url.matches(REGEX_PREFIX + "chinapress\\.com\\.my" + REGEX_SUFFIX)) {//马来西亚中国报
            return trimURL(url, false, "p");
        }
        if (url.matches(REGEX_PREFIX + "chinarightsia\\.org" + REGEX_SUFFIX)) {//中国权利在行动
            return trimURL(url, false, "p", "cat");
        }
        if (url.matches(REGEX_PREFIX + "play\\.google\\.com" + REGEX_SUFFIX)) {//谷歌play
            return trimURL(url, false, "id");
        }
        if (url.matches(REGEX_PREFIX + "now\\.com" + REGEX_SUFFIX)) {//电讯盈科
            return trimURL(url, false, "newsId");
        }
        if (url.matches(REGEX_PREFIX + "forms\\.office\\.com" + REGEX_SUFFIX)) {//office
            return trimURL(url, false, "id");
        }
        if (url.matches(REGEX_PREFIX + "redd(it\\.com|\\.it)" + REGEX_SUFFIX)) {//reddit
            return trimURL(url, false, "context","width","s","auto");
        }
        if (url.matches(REGEX_PREFIX + "tw(itter|img)\\.com" + REGEX_SUFFIX)) {//twitter
            return trimURL(url, false, "s");
        }
        if (url.matches(REGEX_PREFIX + "wik(i(news|pedia)|tionary)\\.org" + REGEX_SUFFIX)) {//维基
            return trimURL(url, false, "title", "action", "section", "curid", "diff", "oldid");
        }
        if (url.matches(REGEX_PREFIX + "youtu(be\\.com|\\.be)" + REGEX_SUFFIX)) {//youtube
            return trimURL(url, false, "v", "t");
        }
        if (url.matches(REGEX_PASS)) {
            setLevel(Level.PASS);
//			LOG.info(level+" "+url);
            return url;
        }
        if (!isTarget) {//未安检过且未解析
            try {
                url = getURLTarget(url);
                return checkURL(url, true);
            } catch (IllegalArgumentException | IOException e) {
                e.printStackTrace();
//				setLevel(Level.OTHER_WARN);
//				return url;
            }
        }
        setLevel(Level.OTHER_WARN);
        Bot.LOG.warning(message.getFrom().getID() + " " + message.getLinkOrPrivateID() + "\n" + level + " " + url);
        return url;
    }

    private void setLevel(Level l) {
        if (l.compareTo(level) > 0) {
            level = l;
        }
    }

    /**
     * @param url          原链接
     * @param isWarn       是否为访问不安全类型
     * @param allowedParas 要保留的参数
     * @return 仅保留指定参数的url
     */
    private String trimURL(String url, final boolean isWarn, final String... allowedParas) {
//		final String regex=isWarn?REGEX_SAFE_WARN:REGEX_SAFE;
        final Level safeLevel = isWarn ? Level.SAFE_WARN : Level.SAFE;
        final Level repostLevel = isWarn ? Level.REPOST_WARN : Level.REPOST;
        int index = url.indexOf("?");
        if (index == -1) {//无参
            setLevel(safeLevel);
//			LOG.info(level+" "+url);
            return url;
        }//有参
        if (allowedParas.length == 0) {//截取
            setLevel(repostLevel);
//            Bot.LOG.info(level + " " + url);
            System.out.println(level + " " + url);
            return url.substring(0, index);
        }
        HttpUrl http = HttpUrl.get(url);
        HashSet<String> parasSet = new HashSet<>(http.queryParameterNames());
        HashSet<String> safeParasSet = new HashSet<>(Arrays.asList(allowedParas));
        parasSet.removeAll(safeParasSet);
        if (parasSet.isEmpty()) {//没有多余参数
            setLevel(safeLevel);
//			LOG.info(level+" "+url);
            return url;
        }//有多余参数
        setLevel(repostLevel);
//        Bot.LOG.info(level + " " + url);
        System.out.println(level + " " + url);
        url = url.substring(0, index);
        HttpUrl.Builder httpBuilder = HttpUrl.get(url).newBuilder();
        for (String allowedPara : allowedParas) {
            String value = http.queryParameter(allowedPara);
            if (null != value) {
                httpBuilder.addQueryParameter(allowedPara, value);
            }
        }
        return httpBuilder.toString();
    }

    /**
     * 检测跳转目标 url
     *
     * @param url 原始 url
     * @return 原始url或目标url
     */
    private String getURLTarget(String url) throws IllegalArgumentException, IOException {
        HttpUrl source = HttpUrl.get(url);
        Request request = new Request.Builder().url(source).head().addHeader("Accept-Language", "zh,zh-CN,zh-HK,zh-TW,zh-SG,zh-MY,zh-Hans,zh-Hant,*;q=0.9").build();
        Call call = client.newCall(request);
        Response response = call.execute();
        int code = response.code();
//            String contentLanguage=response.header("Content-Language");
        HttpUrl target = response.request().url();
        response.close();
        String newURL = target.toString();
        if (code == 301 || code == 302) {
            return getURLTarget(newURL);
        }
//            if(contentLanguage!=null&&!contentLanguage.contains("zh")){//可能是非中文网站
//                throw new RuntimeException("Content-Language");
//            }
        if (source.host().equals(target.host()) && source.encodedPath().equals(target.encodedPath())) {//链接与之前的主体部分一样
            return url;
        }
        return newURL;
    }

    private enum Level {
        PASS,//绝对安全，不检查，不提示
        SAFE,//隐私安全，不删除；访问安全，不提示
        SAFE_WARN,//隐私安全，不删除；访问不安全，提示
        OTHER_WARN,//冷门网站，提示、不删除
        REPOST,//隐私不安全，删除，重发；访问安全，提示
        REPOST_WARN,//隐私不安全，删除，重发；访问不安全，提示
        ARCHIVE,//无法脱敏建议存档，提示、删除
//        CLOUD,//网盘，提示、删除
    }
}
package com.apifest.oauth20.utils;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.net.InetSocketAddress;

/**
 *
 *
 * @author Edouard De Oliveira
 */
public class MDCLogHandler
	extends SimpleChannelUpstreamHandler
{
    private Logger log = LoggerFactory.getLogger(MDCLogHandler.class);

    private void buildClientId(Channel channel) {
        String remoteAddress = ((InetSocketAddress) channel.getRemoteAddress()).getAddress().getHostAddress();
        StringBuilder sb = new StringBuilder("<");
        sb.append(remoteAddress).append(':');
        sb.append(Integer.toHexString(channel.getId()));
        sb.append(">");
        MDC.put("clientId", sb.toString());
    }

    @Override
    public void channelOpen(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        buildClientId(ctx.getChannel());
        log.trace("Channel open");
        ctx.sendUpstream(e);
    }

    @Override
    public void channelBound(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        buildClientId(ctx.getChannel());
        ctx.sendUpstream(e);
    }

    @Override
    public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        log.trace("Channel closed");
        ctx.sendUpstream(e);
    }
}

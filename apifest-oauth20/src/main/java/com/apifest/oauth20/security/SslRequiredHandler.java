package com.apifest.oauth20.security;

import java.net.InetSocketAddress;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.handler.codec.frame.FrameDecoder;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.ssl.SslHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apifest.oauth20.Response;

public class SslRequiredHandler
	extends FrameDecoder
{
	private SslHandler handler;
	
	protected Logger log = LoggerFactory.getLogger(SslRequiredHandler.class);

	public SslRequiredHandler(SslHandler sslHandler) {
		this.handler = sslHandler;
	}

	private void sendHttpResponse(HttpResponseStatus status, String msg, ChannelHandlerContext ctx, ChannelBuffer buffer) {
		HttpResponse httpResponse = Response.createResponse(status, msg);
		ctx.getChannel().write(httpResponse);
		buffer.skipBytes(buffer.readableBytes());
	}
	
	@Override
	protected Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) {
		// Will use the first 5 bytes to detect a protocol.
		if (buffer.readableBytes() < 5)
			return null;

		String addr = ((InetSocketAddress) ctx.getChannel().getRemoteAddress()).getAddress().getHostAddress();
		log.info("Client connection from "+addr+" ...");
		
		ChannelPipeline p = ctx.getPipeline();		
		
		if (SslHandler.isEncrypted(buffer)) {
			p.addBefore("decoder", "ssl", handler);
			p.remove(this);
			
			// Forward the current read buffer as is to the new handlers.
			return buffer.readBytes(buffer.readableBytes());
		} else {
			final int magic1 = buffer.getUnsignedByte(buffer.readerIndex());
			final int magic2 = buffer.getUnsignedByte(buffer.readerIndex() + 1);
			if (isHttp(magic1, magic2)) {
				sendHttpResponse(HttpResponseStatus.UPGRADE_REQUIRED, 
		        			"Only accepts secured connections", ctx, buffer);			
				return null;
			} else {
				// Unknown protocol; discard everything and close the connection.
				buffer.skipBytes(buffer.readableBytes());
				ctx.getChannel().close();
				return null;
			}
		}
	}

	private static boolean isHttp(int magic1, int magic2) {
		return magic1 == 'G' && magic2 == 'E' || // GET
				magic1 == 'P' && magic2 == 'O' || // POST
				magic1 == 'P' && magic2 == 'U' || // PUT
				magic1 == 'H' && magic2 == 'E' || // HEAD
				magic1 == 'O' && magic2 == 'P' || // OPTIONS
				magic1 == 'P' && magic2 == 'A' || // PATCH
				magic1 == 'D' && magic2 == 'E' || // DELETE
				magic1 == 'T' && magic2 == 'R' || // TRACE
				magic1 == 'C' && magic2 == 'O'; // CONNECT
	}
}

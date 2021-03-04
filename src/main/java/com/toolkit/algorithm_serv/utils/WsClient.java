package com.toolkit.algorithm_serv.utils;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.springframework.stereotype.Component;

import javax.websocket.ContainerProvider;
import javax.websocket.WebSocketContainer;
import java.net.URI;
import java.net.URISyntaxException;

public class WsClient extends WebSocketClient {

    public WsClient(String serverUri) throws URISyntaxException {
        super(new URI(serverUri));
    }

    @Override
    public void onOpen(ServerHandshake serverHandshake) {
        System.out.println("握手...");
    }

    @Override
    public void onMessage(String msg) {
        System.out.println("接收到消息：" + msg);
    }

    @Override
    public void onClose(int i, String s, boolean b) {
        System.out.println("关闭...");
    }

    @Override
    public void onError(Exception e) {
        System.out.println("异常" + e);
    }

}

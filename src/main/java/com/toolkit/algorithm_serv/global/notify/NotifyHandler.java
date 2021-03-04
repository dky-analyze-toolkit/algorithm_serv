package com.toolkit.algorithm_serv.global.notify;

import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import com.toolkit.algorithm_serv.utils.WsClient;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import javax.websocket.ContainerProvider;
import javax.websocket.DeploymentException;
import javax.websocket.WebSocketContainer;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@Component
public class NotifyHandler {
    @Value("${websocket.uri}")
    private String serverUri;
    @Value("${websocket.channel}")
    private String channel;

    private String thisID;

    // private static WebSocketContainer container = null;
    private static WsClient wsClient = null;

    @Autowired
    public NotifyHandler() {
        thisID = StrAuxUtils.generateUuid();
    }

    private void autoConnect() throws URISyntaxException, IOException, DeploymentException {
        String uri = StrUtil.join("/", serverUri, channel, thisID);
        System.out.println(uri);
        if (wsClient == null) {
            wsClient = new WsClient(uri);
            wsClient.connect();
        }
    }

    public void sendMsg(String action, String category, Object payload) {
        try {
            autoConnect();

            JSONObject msgObj = new JSONObject();
            msgObj.put("action", action);
            msgObj.put("category", category);
            msgObj.put("payload", payload);

            wsClient.send(msgObj.toJSONString());
        } catch (URISyntaxException | IOException | DeploymentException e) {
            e.printStackTrace();
        }
    }

    public void sendToClient(String clientID, Object payload) {
        sendMsg("send_client_message", clientID, payload);
    }

    public void broadcastChannel(String category, Object payload) {
        sendMsg("broadcast_channel", category, payload);
    }
}

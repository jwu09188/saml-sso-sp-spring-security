package cn.jwutogo.web.sp.config;

import com.sun.istack.internal.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;


/**
 * @Author: WuJiaGen
 * @Date: 2020/7/20 14:01
 */
@Data
@Validated
@ConfigurationProperties("sso.saml.sp")
public class SpSecurityProperties {
    /**
     * idp元数据获取地址
     */
    @NotNull
    private String idpMetadataUrl;

    /**
     * sp实体id
     */
    @NotNull
    private String spEntityId;

    /**
     * 密钥库的密码
     */
    @NotNull
    private String spPassphrase;

    /**
     * 私钥
     */
    @NotNull
    private String spPrivateKey;

    /**
     * 证书
     */
    @NotNull
    private String spCertificate;

    /**
     * idp服务发现配置
     */
    @NotNull
    private String idpDiscoveryService;

    /**
     * 登录成功跳转地址
     */
    private String redirectionAfterSuccessfulUrl;

    /**
     * 注销成功跳转地址
     */
    private String successfulLogoutJumpUrl;
}

package cn.jwutogo.web.sp.service.impl;


import cn.jwutogo.web.sp.config.GenericResponse;
import cn.jwutogo.web.sp.config.HttpRequestUtils;
import cn.jwutogo.web.sp.config.SpSecurityProperties;
import cn.jwutogo.web.sp.service.SamlSpLoginService;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Objects;

/**
 * @Author: WuJiaGen
 * @Date: 2020/7/14 11:27
 */
@Service
@EnableConfigurationProperties(value = {SpSecurityProperties.class})
@Slf4j
public class SamlSpLoginServiceImpl implements SamlSpLoginService {

    private final SpSecurityProperties securityProperties;
    private static final String REQUEST_TYPE = "XMLHttpRequest";
    private static final String REQUEST_HEADER = "X-Requested-With";
    private static final int LOGIN_ERRCODE = 102022009;

    @Autowired
    private SAMLProcessingFilter samlWebSSOProcessingFilter;
    @Autowired
    public SamlSpLoginServiceImpl(SpSecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Override
    public GenericResponse<String> loginCheck(User user, HttpServletRequest request, HttpServletResponse response) {
        if (request.getSession() == null) {
            return new GenericResponse<>(LOGIN_ERRCODE, "需要去sso登录");
        } else {
            if (user == null) {
                return new GenericResponse<>(LOGIN_ERRCODE, "需要去sso登录");
            } else {
                String username = user.getUsername();
                JSONObject json = new JSONObject();
                json.put("username", username);
                String userMessage = json.toJSONString();
                return new GenericResponse<>(userMessage);
            }
        }
    }

    @Override
    public GenericResponse<String> loginRedirect(HttpServletRequest request, HttpServletResponse response,
                                                 String successfulUrl) {
        if (Objects.isNull(successfulUrl)) {
            return new GenericResponse<>(LOGIN_ERRCODE, "Please set the redirect address for successful login");
        } else {
            //添加登录成功后跳转地址
            SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
                    new SavedRequestAwareAuthenticationSuccessHandler();
            successRedirectHandler.setDefaultTargetUrl(successfulUrl);
            samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler);
        }
        String requestHttpHost = HttpRequestUtils.getRequestHttpHost(request);
        String loginUrl = requestHttpHost + "/saml-sso/sp/login?idp=" + securityProperties.getIdpMetadataUrl();
        if (REQUEST_TYPE.equalsIgnoreCase(request.getHeader(REQUEST_HEADER))) {
            JSONObject json = new JSONObject();
            json.put("loginUrl", loginUrl);
            String loginUrlJson = json.toJSONString();
            return new GenericResponse<>(loginUrlJson);
        }
        try {
            response.sendRedirect(loginUrl);
        } catch (Exception e) {
            log.error("重定向失败", e);
        }
        return null;

    }
}

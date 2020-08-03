package cn.jwutogo.web.sp.service;

import cn.jwutogo.web.sp.config.GenericResponse;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @Author: WuJiaGen
 * @Date: 2020/7/14 11:26
 */
public interface SamlSpLoginService {
    /**
     * 登录检查
     *
     * @param user
     * @param request
     * @param response
     * @return UserDto
     */
    GenericResponse<String> loginCheck(User user, HttpServletRequest request, HttpServletResponse response);

    /**
     * 登录重定向
     *
     * @param request
     * @param response
     * @param successfulUrl
     * @return String
     */
    GenericResponse<String> loginRedirect(HttpServletRequest request, HttpServletResponse response,
                                          String successfulUrl);
}

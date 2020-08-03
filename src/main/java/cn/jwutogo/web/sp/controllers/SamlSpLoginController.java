/*
 * Copyright 2020 Vincenzo De Notaris
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cn.jwutogo.web.sp.controllers;

import cn.jwutogo.web.sp.config.GenericResponse;
import cn.jwutogo.web.sp.service.SamlSpLoginService;
import cn.jwutogo.web.sp.stereotypes.CurrentUser;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author WuJiaGen
 * @data 22020-07-15 10:00
 */
@Api(value = "单点登录", tags = "Sp")
@RestController
@RequestMapping(path = "/saml-sso/sp")
public class SamlSpLoginController {
    @Autowired
    private SamlSpLoginService service;


    @ApiOperation("登录检查")
    @RequestMapping(value = "/profile", method = RequestMethod.GET)
    public GenericResponse<String> loginCheck(@CurrentUser User user, HttpServletRequest request,
                                              HttpServletResponse response) {
        return service.loginCheck(user, request, response);
    }

    @ApiOperation("登录重定向")
    @GetMapping(value = "/login-redirect")
    public GenericResponse<String> loginRedirect(String successfulUrl, HttpServletRequest request,
                                                 HttpServletResponse response) {
        return service.loginRedirect(request, response, successfulUrl);

    }

}

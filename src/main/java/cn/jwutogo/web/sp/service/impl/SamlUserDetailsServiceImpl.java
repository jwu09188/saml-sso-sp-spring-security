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

package cn.jwutogo.web.sp.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @Author: WuJiaGen
 * @Date: 2020/7/14 01:17
 */
@Service
@Slf4j
public class SamlUserDetailsServiceImpl implements SAMLUserDetailsService {

    /**
     * 该方法应该标识SAML断言中
     * 数据引用的用户的本地帐户，并返回描述该用户的UserDetails对象。
     *
     * @param credential
     */
    @Override
    public Object loadUserBySAML(SAMLCredential credential)
            throws UsernameNotFoundException {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(authority);
        String userName = credential.getAttributeAsString("cn");
        String userPassword = credential.getAttributeAsString("userPassword");

        /**
         * 在实际情况下，此实现必须根据SAMLCredential中存在的信息将用户定位在任意
         * dataStore中，并以特定于应用程序的UserDetails对象的形式返回
         */
        return new User(userName, userPassword, true, true, true, true, authorities);
    }

}

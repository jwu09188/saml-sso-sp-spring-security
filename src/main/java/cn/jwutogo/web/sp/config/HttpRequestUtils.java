package cn.jwutogo.web.sp.config;

import javax.servlet.http.HttpServletRequest;
import com.google.common.base.Strings;
/**
 * @Author: WuJiaGen
 * @Date: 2020/8/3 15:52
 */
public class HttpRequestUtils {
    public static String getRequestHttpHost(HttpServletRequest request) {
        StringBuilder builder = new StringBuilder();
        String scheme = request.getScheme();
        String forwardedSchema = request.getHeader("X-Forwarded-Proto");
        if (!Strings.isNullOrEmpty(forwardedSchema)) {
            scheme = forwardedSchema;
        }
        builder.append(scheme.toLowerCase())
                .append("://")
                .append(request.getHeader("HOST").toLowerCase());
        return builder.toString();
    }
}

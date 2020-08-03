package cn.jwutogo.web.sp.config;

import lombok.Getter;

import java.util.Date;

/**
 * 响应的基类
 *
 * @author WuJiaGen
 * @data 22020-07-15 10:00
 */

@SuppressWarnings("PMD.AbstractClassWithoutAbstractMethod")
public abstract class BaseResponse {
    /**
     * 错误码
     */
    @Getter
    private int errCode;
    /**
     * 错误消息
     */
    @Getter
    private String errMsg;
    /**
     * 解决错误的办法，如弹窗、跳转
     *
     * @see ErrorResolveTypeEnum
     */
    @Getter
    private String errResolveMethod;

    @Getter
    private final Date timestamp = new Date();

    public BaseResponse(int errCode, String errMsg) {
        this.errCode = errCode;
        this.errMsg = errMsg;
    }

    public BaseResponse(int errCode, String errMsg, String errResolveMethod) {
        this.errCode = errCode;
        this.errMsg = errMsg;
        this.errResolveMethod = errResolveMethod;
    }
}

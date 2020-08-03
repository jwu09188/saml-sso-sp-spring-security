package cn.jwutogo.web.sp.config;

import lombok.Getter;

/**
 * 通用响应
 *
 * @author WuJiaGen
 * @data 22020-07-15 10:00
 */
public class GenericResponse<T> extends BaseResponse {
    /**
     * 消息内容
     */
    @Getter
    private T payload;

    public GenericResponse(int errCode, String errMsg) {
        super(errCode, errMsg);
    }

    public GenericResponse(int errCode, String errMsg, T payload) {
        super(errCode, errMsg);
        this.payload = payload;
    }

    public GenericResponse(T payload) {
        super(0, null);
        this.payload = payload;
    }
}

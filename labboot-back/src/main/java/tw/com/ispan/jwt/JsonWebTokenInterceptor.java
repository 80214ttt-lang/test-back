package tw.com.ispan.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JsonWebTokenInterceptor implements HandlerInterceptor {
    @Autowired
    private JsonWebTokenUtility jsonWebTokenUtility;

    @Override
    public boolean preHandle(HttpServletRequest request,
            HttpServletResponse response, Object handler) throws Exception {
        String method = request.getMethod();
        if("OPTIONS".equals(method)) {
            return true;
        }

        String auth = request.getHeader("Authorization");
        if(auth!=null && auth.startsWith("Bearer ")) {
            String token = auth.substring(7);
            String json = jsonWebTokenUtility.validateToken(token);
            if(json!=null && json.length()!=0) {
                // JSONObject user = new JSONObject(json);
                // String custid = user.getString("custid");
                // 權限授予相關程式碼
                return true;
            }
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Headers", "*");
        return false;
    }
}

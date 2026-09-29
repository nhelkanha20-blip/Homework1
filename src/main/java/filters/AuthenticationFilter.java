package filters;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@WebFilter("/*") 
public class AuthenticationFilter implements Filter {

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpSession session = httpRequest.getSession(false);

        String requestURI = httpRequest.getRequestURI();
        String contextPath = httpRequest.getContextPath();
        String path = requestURI.substring(contextPath.length());

        // Define Public Assets & Authentication endpoints
        boolean isLoginPage = path.endsWith("login.jsp") || path.equals("/login");
        boolean isRegisterPage = path.endsWith("register.jsp") || path.equals("/register");
        boolean isStaticAsset = path.contains("/css/") || path.contains("/js/") || path.contains("/images/");

        boolean loggedIn = (session != null && session.getAttribute("userEmail") != null);
        String role = (loggedIn) ? (String) session.getAttribute("userRole") : "";

        if (loggedIn) {
            // Protect login path from overlapping logged-in states
            if (isLoginPage || isRegisterPage || path.equals("/")) {
                if ("admin".equals(role)) {
                    httpResponse.sendRedirect(contextPath + "/admin/dashboard.jsp");
                } else {
                    httpResponse.sendRedirect(contextPath + "/catalog.jsp");
                }
                return;
            }

            // Enforce admin space restrictions against basic customer credentials
            if (path.startsWith("/admin/") && !"admin".equals(role)) {
                httpResponse.sendRedirect(contextPath + "/catalog.jsp");
                return;
            }

            chain.doFilter(request, response);
        } else {
            // Block all unauthenticated requests looking for secure views
            if (isLoginPage || isRegisterPage || isStaticAsset) {
                chain.doFilter(request, response);
            } else {
                httpResponse.sendRedirect(contextPath + "/login.jsp");
            }
        }
    }

    public void init(FilterConfig fConfig) throws ServletException {}
    public void destroy() {}
}

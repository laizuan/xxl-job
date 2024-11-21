package com.xxl.job.admin.controller.interceptor;

import com.xxl.job.admin.controller.annotation.PermissionLimit;
import com.xxl.job.admin.core.conf.JobProperties;
import com.xxl.job.admin.core.model.XxlJobGroup;
import com.xxl.job.admin.core.model.XxlJobUser;
import com.xxl.job.admin.core.util.I18nUtil;
import com.xxl.job.admin.service.impl.LoginService;
import com.xxl.job.admin.dao.XxlJobUserDao;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.AsyncHandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.util.*;

/**
 * 权限拦截
 *
 * @author xuxueli 2015-12-12 18:09:04
 */
@Component
public class PermissionInterceptor implements AsyncHandlerInterceptor {

    @Resource
    private LoginService loginService;

    @Resource
    private XxlJobUserDao xxlJobUserDao;

    @Resource
    private JobProperties properties;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        if (!(handler instanceof HandlerMethod method)) {
            return true; // proceed with the next interceptor
        }

        String reqAccessUser = request.getHeader("X-Access-User");
        String reqAccessKey = request.getHeader("X-Access-Key");
        if (StringUtils.hasLength(reqAccessKey) && StringUtils.hasLength(reqAccessUser)) {
            String key = properties.getApi().get(reqAccessUser);
            if (!reqAccessKey.equals(key)) {
                throw new RuntimeException(I18nUtil.getString("system_permission_limit"));
            } else {
                XxlJobUser loginUser = xxlJobUserDao.loadByUserName(reqAccessUser);
                if (loginUser == null) {
                    throw new RuntimeException(I18nUtil.getString("login_param_unvalid"));
                }
                request.setAttribute(LoginService.LOGIN_IDENTITY_KEY, loginUser);
                return true;
            }
        }

        // if need login
        boolean needLogin = true;
        boolean needAdminuser = false;
        PermissionLimit permission = method.getMethodAnnotation(PermissionLimit.class);
        if (permission != null) {
            needLogin = permission.limit();
            needAdminuser = permission.adminuser();
        }

		if (needLogin) {
			XxlJobUser loginUser = loginService.ifLogin(request, response);
			if (loginUser == null) {
				response.setStatus(302);
				response.setHeader("location", request.getContextPath()+"/toLogin");
				return false;
			}
			if (needAdminuser && loginUser.getRole()!=1) {
				throw new RuntimeException(I18nUtil.getString("system_permission_limit"));
			}
			request.setAttribute(LoginService.LOGIN_IDENTITY_KEY, loginUser);	// set loginUser, with request
		}

		return true;	// proceed with the next interceptor
	}


	// -------------------- permission tool --------------------

	/**
	 * get loginUser
	 *
	 * @param request
	 * @return
	 */
	public static XxlJobUser getLoginUser(HttpServletRequest request){
		XxlJobUser loginUser = (XxlJobUser) request.getAttribute(LoginService.LOGIN_IDENTITY_KEY);	// get loginUser, with request
		return loginUser;
	}

	/**
	 * valid permission by JobGroup
	 *
	 * @param request
	 * @param jobGroup
	 */
	public static void validJobGroupPermission(HttpServletRequest request, int jobGroup) {
		XxlJobUser loginUser = getLoginUser(request);
		if (!loginUser.validPermission(jobGroup)) {
			throw new RuntimeException(I18nUtil.getString("system_permission_limit") + "[username="+ loginUser.getUsername() +"]");
		}
	}

	/**
	 * filter XxlJobGroup by role
	 *
	 * @param request
	 * @param jobGroupList_all
	 * @return
	 */
	public static List<XxlJobGroup> filterJobGroupByRole(HttpServletRequest request, List<XxlJobGroup> jobGroupList_all){
		List<XxlJobGroup> jobGroupList = new ArrayList<>();
		if (jobGroupList_all!=null && jobGroupList_all.size()>0) {
			XxlJobUser loginUser = PermissionInterceptor.getLoginUser(request);
			if (loginUser.getRole() == 1) {
				jobGroupList = jobGroupList_all;
			} else {
				List<String> groupIdStrs = new ArrayList<>();
				if (loginUser.getPermission()!=null && loginUser.getPermission().trim().length()>0) {
					groupIdStrs = Arrays.asList(loginUser.getPermission().trim().split(","));
				}
				for (XxlJobGroup groupItem:jobGroupList_all) {
					if (groupIdStrs.contains(String.valueOf(groupItem.getId()))) {
						jobGroupList.add(groupItem);
					}
				}
			}
		}
		return jobGroupList;
	}


    /**
     * 升级springboot3 jdk 17
     * spring6移除了对freemarker的jsp支持，
     * 所以导致了内置的Request对象用不了，可以在PermissionInterceptor下添加以下代码
     * <p> 来自issues:
     * <a  href="https://github.com/xuxueli/xxl-job/issues/3338"> https://github.com/xuxueli/xxl-job/issues/3338</a>
     * 感谢 <a  href="https://github.com/zuihou"> @zuihou </a>
     * </p>
     * @param request      请求
     * @param response     响应
     * @param handler      处理对象
     * @param modelAndView 视图
     * @throws Exception 异常
     */
    @Override
    public void postHandle(
            HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView)
            throws Exception {
        if (modelAndView != null) {
            Enumeration<String> enumeration = request.getAttributeNames();
            Map<String, Object> attributes = new HashMap<>();
            while (enumeration.hasMoreElements()) {
                String key = enumeration.nextElement();
                attributes.put(key, request.getAttribute(key));
            }
            modelAndView.addObject("Request", attributes);
        }
    }
}

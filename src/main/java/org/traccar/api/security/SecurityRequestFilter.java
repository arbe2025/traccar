/*
 * Copyright 2015 - 2024 Anton Tananaev (anton@traccar.org)
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

package org.traccar.api.security;

import com.google.inject.Injector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.database.StatisticsManager;
import org.traccar.helper.SessionHelper;
import org.traccar.model.User;
import org.traccar.storage.StorageException;

import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.util.Date;

public class SecurityRequestFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityRequestFilter.class);

    @Context
    private HttpServletRequest request;

    @Context
    private ResourceInfo resourceInfo;

    @Inject
    private LoginService loginService;

    @Inject
    private StatisticsManager statisticsManager;

    @Inject
    private Injector injector;

    @Override
    public void filter(ContainerRequestContext requestContext) {

        if (requestContext.getMethod().equals("OPTIONS")) {
            return;
        }

        // Se elimina la autenticación obligatoria
        SecurityContext securityContext = new UserSecurityContext(new UserPrincipal(0L, new Date(Long.MAX_VALUE)));

        requestContext.setSecurityContext(securityContext);

        LOGGER.info("Acceso permitido sin restricciones para: " + request.getRemoteAddr());
    }
}

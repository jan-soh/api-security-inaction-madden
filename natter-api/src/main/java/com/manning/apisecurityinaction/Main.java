package com.manning.apisecurityinaction;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.SpaceController;
import com.manning.apisecurityinaction.controller.UserController;
import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONException;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.nio.file.Files;
import java.nio.file.Paths;

import static spark.Spark.*;

public class Main {

    public static void main(String... args) throws Exception {

        // enable TLS (HTTPS)
        secure("localhost.p12", "changeit", null, null);

        var datasource = JdbcConnectionPool.create(
                "jdbc:h2:mem:natter", "natter", "password");
        var database = Database.forDataSource(datasource);
        createTables(database);

        datasource = JdbcConnectionPool.create(
                "jdbc:h2:mem:natter", "natter_api_user", "password");
        database = Database.forDataSource(datasource);

        var spaceController =
                new SpaceController(database);

        post("/spaces",
                spaceController::createSpace);

        var userController = new UserController(database);
        post("/users", userController::registerUser);

        // check if the user is authenticated
        before(userController::authenticate);

        var rateLimiter = RateLimiter.create(2.0d);

        before(((request, response) -> {

            // use rate limiting to prevent abuse
            if (!rateLimiter.tryAcquire()) {
                response.header("Retry-After", "2");
                halt(429);
            }

            // ensure that only JSON is accepted (preventing XSS attacks)
            if (request.requestMethod().equals("POST") &&
                    !"application/json".equals(request.contentType())) {
                halt(415, new JSONObject().put(
                        "error", "Only application/json supported"
                ).toString());
            }
        }));

        // always return JSON
        after((request, response) -> {
            response.type("application/json");
        });

        // security headers preventing XSS attacks and other attacks like clickjacking or fingerprinting (hiding the server)
        afterAfter((request, response) -> {
            response.type("application/json;charset=utf-8");
            response.header("X-Content-Type-Options", "nosniff");
            response.header("X-Frame-Options", "DENY");
            response.header("X-XSS-Protection", "0");
            response.header("Cache-Control", "no-store");
            response.header("Content-Security-Policy",
                    "default-src 'none'; frame-ancestors 'none'; sandbox");
            response.header("Server", "");
        });

        internalServerError(new JSONObject()
                .put("error", "internal server error").toString());

        // turn exceptions into appropriate responses
        notFound(new JSONObject()
                .put("error", "not found").toString());
        exception(IllegalArgumentException.class,
                Main::badRequest);
        exception(JSONException.class,
                Main::badRequest);
        exception(EmptyResultException.class,
                (e, request, response) -> response.status(404));
    }

    private static void badRequest(Exception ex,
                                   Request request, Response response) {
        response.status(400);
        // do not expose internal exceptions to the client (only the error message)
        response.body("{\"error\": \"" + ex.getMessage() + "\"}");
    }

    private static void createTables(Database database)
            throws Exception {
        var path = Paths.get(
                Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(path));
    }
}

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <lmdb.h>


constexpr uint64_t strlit(const char * str) {
    uint64_t res = 0;
    for (int i = 0; i < sizeof(uint64_t); i++) {
        if (str[i] == '\0') break;
        uint64_t x = str[i];
        x <<= i*8;
        res += x;
    }
    return res;
}
// constexpr uint64_t operator ""_u64(const char * str, size_t len) {
//     return strlit(str);
// }

template<typename T>
struct Opt {
    struct NullOpt{};
    constexpr static NullOpt null{};
    
    Opt(const T & t) : val(t), set(true) {}
    Opt(NullOpt) : set(false) {}
    operator bool() { return set; }
    operator T() = delete;

    T val;
    bool set = false;
};


struct Database {
    ~Database() {
        if (is_open)
            close();
    }

	void open(const char * path) {
		mdb_env_create(&env);
		// mdb_env_set_maxreaders(env, 1);
		// mdb_env_set_maxdbs(env, 1); // named databases
		// mdb_env_set_mapsize(env, 1024*1024);
		mdb_env_open(env, path, 0/*MDB_FIXEDMAP |MDB_NOSYNC |MDB_NOSUBDIR*/, 0664);
		
		mdb_txn_begin(env, NULL, 0, &txn);
		mdb_dbi_open(txn, NULL, 0, &dbi);

        is_open = true;
	}

	void close() {
		mdb_txn_commit(txn);
		mdb_dbi_close(env, dbi);
		mdb_env_close(env);

        is_open = false;
	}

	template<typename T>
	Opt<T> get(uint64_t a, uint64_t b) {
        uint64_t data[2] = {a,b};
		MDB_val k, v;
		k.mv_data = data;
		k.mv_size = sizeof(data);

		int res =
			mdb_get(txn, dbi, &k, &v);

        if (res == 0 && v.mv_size == sizeof(T)) {
            T t;
			memcpy(&t, v.mv_data, sizeof(T));
            return t;
        }

		return Opt<T>::null;
	}

	template<typename T>
	T set(uint64_t a, uint64_t b, T val) {
        uint64_t data[2] = {a,b};
		MDB_val k, v;
		k.mv_data = data;
		k.mv_size = sizeof(data);
        v.mv_data = &val;
        v.mv_size = sizeof(T);

		int res =
			mdb_put(txn, dbi, &k, &v, 0);

        return val;
	}

	bool del(uint64_t a, uint64_t b) {
        uint64_t data[2] = {a,b};
		MDB_val k, v;
		k.mv_data = data;
		k.mv_size = sizeof(data);

		int res =
			mdb_del(txn, dbi, &k, nullptr);

        return res == MDB_NOTFOUND;
	}

    // template<typename T>
    // T get_or(uint64_t a, uint64_t b, T val) {
    //     auto opt = get<T>(a, b);
    //     return (opt.set ? opt.val : set<T>(a, b, val));
    // }
	
    bool is_open = false;
	MDB_env *env;
	MDB_dbi dbi;
	MDB_txn *txn;
};

/*
int main() {
	Database db;
	db.open("./chirpdb");

    constexpr uint64_t username = strlit("patrick");
    
    constexpr uint64_t _users   = strlit("users");
    constexpr uint64_t _note    = strlit("note");
    constexpr uint64_t _posts   = strlit("posts");
    constexpr uint64_t _count   = strlit("count");
    constexpr uint64_t _text    = strlit("text");

    auto user = db.get<Handle>(_users, username);
    if (user) {
        printf("user found\n");

        auto note = db.get<Str>(user.val, _note);
        if (note)
            printf("note: %s\n", note.val.data);
    }
    else {
        user = db.set(_users, username, rnd());

        if (user)
            db.set<Str>(user.val, _note, "A Note!");
    }

    if (user) {
        auto posts = db.get<Handle>(user.val, _posts);
        if (! posts)
            posts = db.set<Handle>(user.val, _posts, rnd());

        if (posts) {
            auto postCount = db.get<int>(posts.val, _count);
            if (! postCount)
                postCount = db.set<int>(posts.val, _count, 0);

            if (postCount) {
                for (int i = 0; i < postCount.val; i++) {
                    auto post = db.get<Handle>(posts.val, i);

                    if (post) {
                        auto text = db.get<Str>(post.val, _text);

                        if (text)
                            printf("%d: %s\n", i, text.val.data);
                    }
                }

                auto newPost = db.set(posts.val, postCount.val, rnd());
                db.set<Str>(newPost, _text, "Hallo");
                db.set<int>(posts.val, _count, postCount.val + 1);
            }
        }
    }

	db.close();

    return 0;
}
*/

#include "../main/http.h"

constexpr int StrSize = 1024;

struct Str {
    Str() {};
    Str(const char * str) { strcpy(data, str); }

    const bool operator== (const char *str) {
        for (int i = 0; str[i] != '\0' && data[i] != '\0'; i++) {
            if (str[i] != data[i]) {
                return false;
            }
        }
        return true;
    }

    char data[StrSize];
};

Str UrlDecode(Str encoded) {
    Str result;

    for (int j = 0, k = 0; encoded.data[k] != '\0'; j++, k++) {
        if (encoded.data[k] == '%') {
            int c;
            sscanf(encoded.data+k+1, "%2x", &c);
            k += 2;
            if (c == '\n')
                j += sprintf(result.data+j, "<br />")-1;
            else
                result.data[j] = (char)c;
        }
        else if (encoded.data[k] == '+') {
            result.data[j] = ' ';
        }
        else {
            result.data[j] = encoded.data[k];
        }
        result.data[j+1] = '\0';
    }

    return result;
}

using Handle = uint64_t;

Handle rnd() {
    Handle res;
    char * ptr = (char*)&res;
    for (int i = 0; i < (int)sizeof(Handle); i++)
        ptr[i] = rand() % 256;
    return res;
}


constexpr int UsernameSize = 8;
constexpr int PasswordSize = 64;
constexpr int LoginTokenSize = 64;


constexpr auto _users    = strlit("users");
constexpr auto _posts    = strlit("posts");
constexpr auto _count    = strlit("count");
constexpr auto _text     = strlit("text");
constexpr auto _time     = strlit("time");
constexpr auto _author   = strlit("author");
constexpr auto _comments = strlit("comments");
constexpr auto _tokens   = strlit("tokens");
constexpr auto _username = strlit("username");
constexpr auto _password = strlit("password");


namespace User {
    Opt<Handle> LoginToken(Database &db, Http *http) {
        // get Cookie header
        HttpHeader *cookieHeader =
            http_find_header(http, "Cookie");
        if (cookieHeader == nullptr)
            return Opt<Handle>::null;
        
        // check login token
        Handle loginToken;
        if (sscanf(cookieHeader->value, "login_token=%llx", &loginToken) != 1)
            return Opt<Handle>::null;
        
        // serve profile page
        return db.get<Handle>(_tokens, loginToken);
    }
}

namespace Post {
    char * Html(Database &db, Handle postHandle, Opt<Handle> activeUserHandle) {
        constexpr int PostHtmlSize = 1024*10;
        char *html = (char*)malloc(PostHtmlSize);
        int htmlIndex = 0;

        auto text = db.get<Str>(postHandle, _text);
        auto time = db.get<time_t>(postHandle, _time);
        char timeBuffer[32];
        strftime(timeBuffer, 32, "%Y-%m-%d %H:%M:%S", localtime(&time.val));
        auto authorHandle = db.get<Handle>(postHandle, _author);
        auto authorUsername = db.get<Str>(authorHandle.val, _username);

        Str decodedText = UrlDecode(text.val);

        htmlIndex += snprintf(html+htmlIndex, PostHtmlSize-htmlIndex,
            "<div style=\"border: 1px solid black;\">\n"
            "<p>[%s] <a href=\"/posts/%s\">%s</a>:</p>\n"
            "<p>%s</p>\n",
            timeBuffer,
            authorUsername.val.data,
            authorUsername.val.data,
            decodedText.data);
        
        auto comments = db.get<Handle>(postHandle, _comments);
        if (comments) {
            auto commentsCount = db.get<int>(comments.val, _count);

            for (int i = 0; i < commentsCount.val; i++) {
                auto commentHandle = db.get<Handle>(comments.val, i);
                char *commentHtml = Post::Html(db, commentHandle.val, activeUserHandle);
                
                htmlIndex += snprintf(html+htmlIndex, PostHtmlSize-htmlIndex,
                    "%s", commentHtml);
                
                free((void*)commentHtml);
            }
        }
        
        if (activeUserHandle) {
            htmlIndex += snprintf(html+htmlIndex, PostHtmlSize-htmlIndex,
                "<form action=\"/comment\" method=\"post\">\n"
                "<input type=\"hidden\" name=\"post_handle\" value=\"%llx\" />\n"
                "<input type=\"text\"   name=\"text\" autocomplete=\"off\" />\n"
                "<input type=\"submit\" value=\"Comment\" />\n"
                "</form>\n",
                postHandle);
        }

        htmlIndex += snprintf(html+htmlIndex, PostHtmlSize-htmlIndex,
            "</div>\n");
        
        return html;
    }
}

int redirect(char *resbuf, int resbuf_size, const char *path) {
    static char headers[128];
    snprintf(headers, 128, "Location: %s\r\n", path);
    return http_serve(resbuf, resbuf_size, 303, nullptr, headers);
}

int redirect_back(char *resbuf, int resbuf_size, Http *http) {
    static char headers[128];

    HttpHeader *referer = http_find_header(http, "Referer");
    if (referer)
        snprintf(headers, 128, "Location: %s\r\n", referer->value);
    else
        snprintf(headers, 128, "Location: /\r\n");

    return http_serve(resbuf, resbuf_size, 303, nullptr, headers);
}



#define HEAD                                                                   \
"<head>\n"                                                                     \
"<meta charset=\"utf-8\" />\n"                                                 \
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n" \
"<style type=\"text/css\">\n"                                                  \
"body{"                                                                        \
    "margin:40px auto;"                                                        \
    "max-width:650px;"                                                         \
    "line-height:1.2;"                                                         \
    "font-size:18px;"                                                          \
    "color:#444;"                                                              \
    "background-color:#EEE;"                                                   \
    "padding:0 10px"                                                           \
"}"                                                                            \
"h1,h2,h3{"                                                                    \
    "line-height:1.2"                                                          \
"}\n"                                                                          \
"</style>\n"                                                                   \
"</head>\n"


/*
TODO:
- string handling (string writer smth...)
- navigation/css on all pages
- link to posts
*/


extern "C" {
int serve(Http *http, char *resbuf, int resbuf_size) {
    constexpr int HtmlSize = 1024*10;
    char html[HtmlSize];
    
	Database db;
    db.open("./chirp/chirpdb");

    // GET
    if (strcmp(http->method, "GET") == 0) {
        
        if (strcmp(http->uri, "/") == 0) {
            return http_serve(resbuf, resbuf_size, 200,
                "<html>\n"
                HEAD
                "<body>\n"
                "<p>Welcome to Chirp!!!</p>\n"
                "<p><a href=\"/login\">Login</a></p>\n"
                "<p><a href=\"/register\">Register</a></p>\n"
                "</body>\n"
                "</html>\n"
            , nullptr);
        }

        else if (strcmp(http->uri, "/login") == 0) {
            return http_serve(resbuf, resbuf_size, 200,
                "<html>\n"
                HEAD
                "<body>\n"
                "<form action=\"/login\" method=\"post\">\n"
                "<input type=\"text\" placeholder=\"Username\" name=\"username\" />\n"
                "<input type=\"password\" placeholder=\"Password\" name=\"password\" />\n"
                "<input type=\"submit\" value=\"Login\" />\n"
                "</form>\n"
                "</body>\n"
                "</html>\n"
            , nullptr);
        }

        else if (strcmp(http->uri, "/register") == 0) {
            return http_serve(resbuf, resbuf_size, 200,
                "<html>\n"
                HEAD
                "<body>\n"
                "<form action=\"/register\" method=\"post\">\n"
                "<input type=\"text\" placeholder=\"Username\" name=\"username\" />\n"
                "<input type=\"password\" placeholder=\"Password\" name=\"password\" />\n"
                "<input type=\"submit\" value=\"Register\" />\n"
                "</form>\n"
                "</body>\n"
                "</html>\n"
            , nullptr);
        }

        else if (strcmp(http->uri, "/profile") == 0) {
            auto userHandle = User::LoginToken(db, http);

            if (! userHandle)
                return redirect(resbuf, resbuf_size, "/");

            auto username = db.get<Str>(userHandle.val, _username);

            snprintf(html, HtmlSize,
                "<html>\n"
                HEAD
                "<body>\n"
                "<p>%s's profile</p>\n"

                "<form action=\"/change_username\" method=\"post\">\n"
                "<input type=\"text\" placeholder=\"Username\" name=\"username\" />\n"
                "<input type=\"submit\" value=\"Change Username\" />\n"
                "</form>\n"
                
                "<form action=\"/change_password\" method=\"post\">\n"
                "<input type=\"text\" placeholder=\"Password\" name=\"password\" />\n"
                "<input type=\"submit\" value=\"Change Password\" />\n"
                "</form>\n"
                
                "<form action=\"/logout\" method=\"post\">\n"
                "<input type=\"submit\" value=\"Log Out\" />\n"
                "</form>\n"
                
                "<form action=\"/post\" method=\"post\">\n"
                "<textarea name=\"text\"></textarea><br />\n"
                "<input type=\"submit\" value=\"Post\" />\n"
                "</form>\n"

                "</body>\n"
                "</html>\n",
                username.val.data);
            
            return http_serve(resbuf, resbuf_size, 200, html, nullptr);
        }

        else if (strncmp(http->uri, "/posts/", 7) == 0) {
            char username[UsernameSize];
            sscanf(http->uri, "/posts/%s", username);

            auto userHandle = db.get<Handle>(_users, strlit(username));
            if (! userHandle)
                return http_serve(resbuf, resbuf_size, 200, "unknown user", nullptr);

            auto activeUserHandle = User::LoginToken(db, http);

            int htmlIndex = 0;
            htmlIndex += snprintf(html+htmlIndex, HtmlSize-htmlIndex,
                "<html>\n"
                HEAD
                "<body>\n"
                "<h1>Posts by %s</h1>", username);

            auto posts = db.get<Handle>(userHandle.val, _posts);
            if (posts) {
                auto postCount = db.get<int>(posts.val, _count);

                for (int i = postCount.val-1; i >= 0; i--) {
                    auto postHandle = db.get<Handle>(posts.val, i);

                    char *postHtml = Post::Html(db, postHandle.val, activeUserHandle);
                    
                    htmlIndex += snprintf(html+htmlIndex, HtmlSize-htmlIndex,
                        "%s", postHtml);
                    
                    free((void*)postHtml);
                }
            }
            
            htmlIndex += snprintf(html+htmlIndex, HtmlSize-htmlIndex,
                "</body>\n");
            
            return http_serve(resbuf, resbuf_size, 200, html, nullptr);
        }

    }
    // POST
    else if (strcmp(http->method, "POST") == 0) {

        if (strcmp(http->uri, "/login") == 0) {
            static char username[UsernameSize];
            static char password[PasswordSize];
            if (sscanf(http->body, "username=%[^&]&password=%s", username, password) != 2)
                return http_serve(resbuf, resbuf_size, 200, "unable to login", nullptr);

            auto userHandle = db.get<Handle>(_users, strlit(username));
            if (userHandle) {
                auto storedPw = db.get<Str>(userHandle.val, _password);
                if (storedPw && storedPw.val == password) {
                    Handle login_token = rnd();
                    db.set(_tokens, login_token, userHandle.val);

                    char headers[128];
                    snprintf(headers, 128,
                        "Location: /profile\r\n"
                        "Set-Cookie: login_token=%llx\r\n",//Domain=chirp.psch.dev
                        login_token);
                    return http_serve(resbuf, resbuf_size, 303, nullptr, headers);
                }
            }
            
            return http_serve(resbuf, resbuf_size, 200, "unable to login", nullptr);
        }

        else if (strcmp(http->uri, "/register") == 0) {
            static char username[UsernameSize];
            static char password[PasswordSize];
            if (sscanf(http->body, "username=%[^&]&password=%s", username, password) != 2)
                return http_serve(resbuf, resbuf_size, 200, "unable to login", nullptr);

            auto existingUserHandle = db.get<Handle>(_users, strlit(username));
            if (existingUserHandle)
                return http_serve(resbuf, resbuf_size, 200, "user already registered", nullptr);

            auto userHandle = rnd();
            db.set(userHandle, _username, Str(username));
            db.set(userHandle, _password, Str(password));

            db.set(_users, strlit(username), userHandle);

            printf("registered %s (handle %llx)\n", username, userHandle);
            
            Handle login_token = rnd();
            db.set(_tokens, login_token, userHandle);

            char headers[128];
            snprintf(headers, 128,
                "Location: /profile\r\n"
                "Set-Cookie: login_token=%llx\r\n",//Domain=chirp.psch.dev
                login_token);
            return http_serve(resbuf, resbuf_size, 303, nullptr, headers);
        }

        else if (strcmp(http->uri, "/change_username") == 0) {
            static char username[UsernameSize];
            if (sscanf(http->body, "username=%s", username) != 1)
                return http_serve(resbuf, resbuf_size, 200, "unable to change username: no username provided", nullptr);
            
            if (db.get<Handle>(_users, strlit(username)))
                return http_serve(resbuf, resbuf_size, 200, "unable to change username: username already in use", nullptr);
            
            auto userHandle = User::LoginToken(db, http);
            if (! userHandle)
                return http_serve(resbuf, resbuf_size, 200, "unable to change username: not logged in", nullptr);
            
            auto oldUsername = db.get<Str>(userHandle.val, _username);

            if (oldUsername) {
                printf("deleting old username %s\n", oldUsername.val.data);
                db.del(_users, strlit(oldUsername.val.data));
            }
            printf("setting username to %s\n", username);
            db.set(_users, strlit(username), userHandle.val);

            db.set(userHandle.val, _username, Str(username));

            return redirect_back(resbuf, resbuf_size, http);
        }

        else if (strcmp(http->uri, "/change_password") == 0) {
            static char password[PasswordSize];
            if (sscanf(http->body, "password=%s", password) != 1)
                return http_serve(resbuf, resbuf_size, 200, "unable to change password: no password provided", nullptr);
            
            auto userHandle = User::LoginToken(db, http);
            if (! userHandle)
                return http_serve(resbuf, resbuf_size, 200, "unable to change password: not logged in", nullptr);

            db.set(userHandle.val, _password, Str(password));

            return redirect_back(resbuf, resbuf_size, http);
        }
        
        else if (strcmp(http->uri, "/logout") == 0) {
            char headers[128];
            snprintf(headers, 128,
                "Location: /\r\n"
                "Set-Cookie: login_token=;Max-Age=0\r\n");
            return http_serve(resbuf, resbuf_size, 303, nullptr, headers);
        }

        else if (strcmp(http->uri, "/post") == 0) {
            Str text;
            if (sscanf(http->body, "text=%s", text.data) != 1)
                return http_serve(resbuf, resbuf_size, 200, "unable to post: no text provided", nullptr);

            auto userHandle = User::LoginToken(db, http);
            if (userHandle) {
                auto posts = db.get<Handle>(userHandle.val, _posts);
                if (! posts)
                    posts = db.set<Handle>(userHandle.val, _posts, rnd());
                
                auto postCount = db.get<int>(posts.val, _count);
                if (! postCount)
                    postCount = db.set<int>(posts.val, _count, 0);
                    
                auto newPost = db.set(posts.val, postCount.val, rnd());
                db.set<Str>(newPost, _text, text);
                db.set<time_t>(newPost, _time, time(nullptr));
                db.set<Handle>(newPost, _author, userHandle.val);
                db.set<int>(posts.val, _count, postCount.val + 1);
            }

            return redirect_back(resbuf, resbuf_size, http);
        }

        else if (strcmp(http->uri, "/comment") == 0) {
            Handle postHandle;
            Str text;
            if (sscanf(http->body, "post_handle=%llx&text=%s", &postHandle, text.data) != 2)
                return http_serve(resbuf, resbuf_size, 200, "unable to comment: no text provided", nullptr);

            auto userHandle = User::LoginToken(db, http);
            if (userHandle) {
                auto comments = db.get<Handle>(postHandle, _comments);
                if (! comments)
                    comments = db.set<Handle>(postHandle, _comments, rnd());
                
                auto commentCount = db.get<int>(comments.val, _count);
                if (! commentCount)
                    commentCount = db.set<int>(comments.val, _count, 0);
                    
                auto newComment = db.set(comments.val, commentCount.val, rnd());
                db.set<Str>(newComment, _text, text);
                db.set<time_t>(newComment, _time, time(nullptr));
                db.set<Handle>(newComment, _author, userHandle.val);
                db.set<int>(comments.val, _count, commentCount.val + 1);
            }

            return redirect_back(resbuf, resbuf_size, http);
        }

    }

    return redirect(resbuf, resbuf_size, "/");
}
}
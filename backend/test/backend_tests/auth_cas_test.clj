;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.

(ns backend-tests.auth-cas-test
  (:require
   [app.config :as cf]
   [app.http.client :as http]
   [app.rpc.commands.cas :as cas]
   [app.util.json :as json]
   [clojure.test :as t]))

(t/deftest cas-ticket-validation
  (let [request (atom nil)]
    (with-redefs [cf/get (fn [_] "http://cas.example/authToken")
                  http/req (fn [_ req _]
                             (reset! request req)
                             {:status 200
                              :body (json/encode-str
                                     {:code 0
                                      :props {:user {:userBaseInfo
                                                     {:userEmail " USER@example.com "
                                                      :userNameCh "User"}}}})})]
      (t/is (= {:email "user@example.com" :fullname "User" :backend "cas"}
               (#'cas/get-cas-identity {} "a+b&c")))
      (t/is (= "http://cas.example/authToken?token=a%2Bb%26c" (:uri @request))))))

(t/deftest cas-rejects-invalid-responses
  (doseq [response [{:status 500}
                    {:status 200 :body "invalid json"}
                    {:status 200 :body "{\"code\":1}"}
                    {:status 200 :body "{\"code\":0,\"props\":{}}"}]]
    (with-redefs [cf/get (fn [_] "http://cas.example/authToken")
                  http/req (fn [& _] response)]
      (t/is (thrown? clojure.lang.ExceptionInfo
                     (#'cas/get-cas-identity {} "ticket"))))))

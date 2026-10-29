;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.

(ns app.rpc.commands.cas
  (:require
   [app.common.exceptions :as ex]
   [app.common.schema :as sm]
   [app.config :as cf]
   [app.db :as db]
   [app.http.client :as http]
   [app.http.session :as session]
   [app.loggers.audit :as-alias audit]
   [app.rpc :as-alias rpc]
   [app.rpc.commands.auth :as auth]
   [app.rpc.commands.profile :as profile]
   [app.rpc.doc :as-alias doc]
   [app.rpc.helpers :as rph]
   [app.util.json :as json]
   [app.util.services :as sv]
   [clojure.string :as str])
  (:import java.net.URLEncoder))

(defn- get-cas-identity
  [cfg token]
  (let [uri (cf/get :cas-auth-uri)]
    (when (str/blank? uri)
      (ex/raise :type :restriction :code :cas-not-configured))
    (let [response (try
                     (http/req cfg {:method :get
                                    :uri (str uri "?token=" (URLEncoder/encode token "UTF-8"))
                                    :timeout 5000}
                               {:skip-ssrf-check? true})
                     (catch Exception _ nil))
          data     (when (= 200 (:status response))
                     (try (json/decode (:body response))
                          (catch Exception _ nil)))
          info     (get-in data [:props :user :userBaseInfo])
          email    (:userEmail info)]
      (when-not (and (= 0 (:code data))
                     (string? email)
                     (sm/check ::sm/email (str/trim email)))
        (ex/raise :type :validation :code :cas-authentication-failed))
      {:email (profile/clean-email (str/trim email))
       :fullname (if (and (string? (:userNameCh info))
                          (not (str/blank? (:userNameCh info))))
                   (:userNameCh info)
                   email)
       :backend "cas"})))

(sv/defmethod ::login-with-cas
  "Authenticate a CAS ticket and create a Penpot session."
  {::rpc/auth false
   ::doc/module :auth
   ::audit/skip true
   ::sm/params [:map [:token [:string {:min 1 :max 4096}]]]}
  [cfg {:keys [token]}]
  (let [info    (get-cas-identity cfg token)
        profile (db/tx-run! cfg
                  (fn [{:keys [::db/conn] :as cfg}]
                    (or (profile/get-profile-by-email conn (:email info))
                        (->> (assoc info :is-active true :is-demo false)
                             (auth/create-profile cfg)
                             (auth/create-profile-rels cfg)))))]
    (-> (profile/strip-private-attrs profile)
        (rph/with-transform (session/create-fn cfg profile))
        (rph/with-meta {::audit/replace-props {}
                        ::audit/profile-id (:id profile)}))))

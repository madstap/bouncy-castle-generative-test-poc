(ns bouncy-test
  (:require [clojure.test :refer [deftest testing is]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [clojure.test.check :as tcheck]
            [clojure.test.check.clojure-test :refer [defspec]])
  (:import (org.bouncycastle.crypto.generators OpenBSDBCrypt)))

(def cost-factor 4)

(def gen-salt
  (gen/fmap byte-array (gen/vector gen/byte 16)))

(def right (.toCharArray "test-token"))
(def wrong (.toCharArray "wrong-token"))

(def wrong-password-should-fail-prop
  (prop/for-all [salt gen-salt]
    (let [pwhash (OpenBSDBCrypt/generate right salt cost-factor)]
      (and (OpenBSDBCrypt/checkPassword pwhash right)
           (not (OpenBSDBCrypt/checkPassword pwhash wrong))))))

(def gen-passwords
  (->> (apply gen/tuple (repeat 2 gen/string-alphanumeric))
       (gen/such-that (fn [[right wrong]] (not= right wrong)))))

(def wrong-password-should-fail-prop2
  (prop/for-all [[right wrong] gen-passwords
                 salt gen-salt]
    (let [pwhash (OpenBSDBCrypt/generate (.toCharArray right) salt cost-factor)]
      (and (OpenBSDBCrypt/checkPassword pwhash (.toCharArray right))
           (not (OpenBSDBCrypt/checkPassword pwhash (.toCharArray wrong)))))))

(defspec wrong-password-test 1000
  wrong-password-should-fail-prop)

(defspec wrong-password-test2 1000
  wrong-password-should-fail-prop2)

(deftest wrong-password-should-fail-unit
  (testing "Extracted from wrong-password-should-fail-prop with :seed 1608403604053"
    (let [salt (byte-array [-39 19 -60 77 73 -14 -77 63 -50 -33 91 96 47 -21 -67 0])
          pwhash (OpenBSDBCrypt/generate right salt cost-factor)]
      (is (and (OpenBSDBCrypt/checkPassword pwhash right)
               (not (OpenBSDBCrypt/checkPassword pwhash wrong)))))))

(comment
  (tcheck/quick-check 1000 wrong-password-should-fail-prop :seed 1608403604053)

  (tcheck/quick-check 1000 wrong-password-should-fail-prop2)

  )

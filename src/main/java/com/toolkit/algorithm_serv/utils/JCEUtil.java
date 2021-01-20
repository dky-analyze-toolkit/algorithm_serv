package com.toolkit.algorithm_serv.utils;

import java.lang.reflect.Field;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JCEUtil {
    private static Logger logger = Logger.getLogger(JCEUtil.class.getName());

    /**
     * Remove Cryptography Restrictions
     * @author ntoskrnl
     * @see ://stackoverflow.com/questions/1179672/how-to-avoid-installing-unlimited-strength-jce-policy-files-when-deploying-an
     *
     * Sometime app need uses 256-bit AES encryption,
     * usually we need install “Unlimited Strength” JCE policy files,
     * or skip the JCE API and use another cryptography library such as Bouncy Castle.
     *
     * ! Use another cryptography library's JCEProvider cant skip key strength restrictions !
     * So that code using reflection to change permissions without deploy any jar file.
     */
    public static void removeCryptographyRestrictions() {
        if (!isRestrictedCryptography()) {
            logger.fine("Cryptography restrictions removal not needed");
            return;
        }
        try {
            /*
             * Do the following, but with reflection to bypass access checks:
             *
             * JceSecurity.isRestricted = false;
             * JceSecurity.defaultPolicy.perms.clear();
             * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
             */
            final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

            final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            isRestrictedField.set(null, false);

            final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicyField.setAccessible(true);
            final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

            final Field perms = cryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);
            ((Map<?, ?>) perms.get(defaultPolicy)).clear();

            final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            defaultPolicy.add((Permission) instance.get(null));

            logger.fine("Successfully removed cryptography restrictions");
        } catch (final Exception e) {
            logger.log(Level.WARNING, "Failed to remove cryptography restrictions", e);
        }
    }

    /**
     * Check JVM is Oracle JRE not OpenJDK
     * @author ntoskrnl
     * @see ://stackoverflow.com/questions/1179672/how-to-avoid-installing-unlimited-strength-jce-policy-files-when-deploying-an
     */
    private static boolean isRestrictedCryptography() {
        // This simply matches the Oracle JRE, but not OpenJDK.
        return "Java(TM) SE Runtime Environment".equals(System.getProperty("java.runtime.name"));
    }
}


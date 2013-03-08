package org.thoughtcrime.ssl.pinning.test;


import android.test.AndroidTestCase;

import org.thoughtcrime.ssl.pinning.SystemKeyStore;

public class SystemKeyStoreTest extends AndroidTestCase {

  public void testConstruction() {
    assertNotNull(SystemKeyStore.getInstance(getContext()));
  }

}

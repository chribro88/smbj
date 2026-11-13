/*
 * Copyright (C)2016 - SMBJ Contributors
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
package com.hierynomus.protocol.commons.concurrent;

import com.hierynomus.smbj.common.SMBRuntimeException;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

public class CancellableFuture<V> extends AFuture<V> {
    private final AFuture<V> wrappedFuture;
    private final CancelCallback callback;

    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public CancellableFuture(AFuture<V> wrappedFuture, CancelCallback cc) {
        this.wrappedFuture = wrappedFuture;
        this.callback = cc;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        if (wrappedFuture.isDone() || !cancelled.compareAndSet(false, true)) {
            return false;
        }
        try {
            callback.cancel();
            return true;
        } catch (RuntimeException e) {
            throw SMBRuntimeException.Wrapper.wrap(e);
        }
    }

    @Override
    public boolean isCancelled() {
        return cancelled.get();
    }

    @Override
    public boolean isDone() {
        return cancelled.get() || wrappedFuture.isDone();
    }

    @Override
    public V get() throws InterruptedException, ExecutionException {
        checkCancelled();
        try {
            V value = wrappedFuture.get();
            checkCancelled();
            return value;
        } catch (ExecutionException e) {
            checkCancelled();
            throw e;
        }
    }

    @Override
    public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        checkCancelled();
        try {
            V value = wrappedFuture.get(timeout, unit);
            checkCancelled();
            return value;
        } catch (ExecutionException e) {
            checkCancelled();
            throw e;
        }
    }

    private void checkCancelled() {
        if (cancelled.get()) {
            throw new CancellationException("Request cancelled");
        }
    }

    public interface CancelCallback {
        void cancel();
    }
}

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
package com.hierynomus.smbj.connection;

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB3SigningAlgorithm;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.DerivationFunction;
import com.hierynomus.security.MessageDigest;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.jce.derivationfunction.CounterDerivationParameters;
import com.hierynomus.smb.Packets;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.auth.NtlmSealer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.session.SMB2GuestSigningRequiredException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.session.SessionContext;
import com.hierynomus.smbj.utils.DigestUtil;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenInit2;
import com.hierynomus.spnego.SpnegoException;
import com.hierynomus.spnego.SpnegoToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static com.hierynomus.mssmb2.SMB2MessageFlag.SMB2_FLAGS_SIGNED;
import static com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED;
import static com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED;
import static com.hierynomus.utils.Strings.nullTerminatedBytes;
import static java.lang.String.format;

/**
 * [MS-SMB2] 3.2.5.3.1 Handling a New Authentication
 */
public class SMBSessionBuilder {

    static final byte[] KDF_ENC_LABEL_SMB311 = nullTerminatedBytes("SMBC2SCipherKey");
    static final byte[] KDF_DEC_LABEL_SMB311 = nullTerminatedBytes("SMBS2CCipherKey");
    static final byte[] KDF_ENCDEC_LABEL = nullTerminatedBytes("SMB2AESCCM");
    static final byte[] KDF_ENC_CONTEXT = nullTerminatedBytes("ServerIn ");
    static final byte[] KDF_DEC_CONTEXT = nullTerminatedBytes("ServerOut");
    static final byte[] KDF_SIGN_CONTEXT = nullTerminatedBytes("SmbSign");
    static final byte[] KDF_SIGN_LABEL = nullTerminatedBytes("SMB2AESCMAC");
    static final byte[] KDF_SIGN_LABEL_SMB311 = nullTerminatedBytes("SMBSigningKey");
    static final byte[] KDF_APP_CONTEXT = nullTerminatedBytes("SmbRpc");
    static final byte[] KDF_APP_LABEL = nullTerminatedBytes("SMB2APP");
    static final byte[] KDF_APP_LABEL_SMB311 = nullTerminatedBytes("SMBAppKey");
    static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    static final String AES_128_CMAC_ALGORITHM = "AesCmac";


    private static final Logger logger = LoggerFactory.getLogger(SMBSessionBuilder.class);
    private final SmbConfig config;
    private final ConnectionContext connectionContext;
    private final SessionFactory sessionFactory;
    private final SessionTable sessionTable;
    private final SessionTable preauthSessionTable;
    private final Connection connection;

    public SMBSessionBuilder(Connection connection, SmbConfig config, SessionFactory sessionFactory) {
        this.connection = connection;
        this.config = config;
        this.connectionContext = connection.getConnectionContext();
        this.sessionTable = connection.getSessionTable();
        this.preauthSessionTable = connection.getPreauthSessionTable();
        this.sessionFactory = sessionFactory;
    }

    /**
     * Establish a new session on the connection using the passed credentials.
     *
     * @return a (new) Session that is authenticated for the user.
     */
    public Session establish(AuthenticationContext authContext) {
        BuilderContext ctx = null;
        boolean published = false;
        try {
            Authenticator authenticator = getAuthenticator(authContext);
            if (authenticator instanceof NtlmAuthenticator && config.getNtlmConfig().isIntegrityEnabled() && !(authContext.isAnonymous() && !(authContext.isGuest()))) {
                authenticator = new NtlmSealer((NtlmAuthenticator) authenticator);
            }

            ctx = newContext(authContext, authenticator);

            authenticator.init(config);
            processAuthenticationToken(ctx, connectionContext.getGssNegotiateToken());

            Session session = setupSession(ctx);
            if (!sessionTable.registerSessionIfAbsent(session.getSessionId(), session)) {
                throw new IOException("Authentication returned an already active SessionId");
            }
            published = true;
            logger.info("Successfully authenticated {} on {}, session is {}", authContext.getUsername(), connection.getRemoteHostname(), session.getSessionId());
            return session;
        } catch (SpnegoException | IOException e) {
            throw new SMBRuntimeException(e);
        } finally {
            if (ctx != null && ctx.session != null) {
                preauthSessionTable.removeSession(ctx.sessionId, ctx.session);
                if (!published) ctx.session.discardUnpublishedAuthentication();
            }
        }
    }

    // CUSTOM ADDED BEGIN: MS-SMB2 3.2.4.2.3 / 3.3.5.5.3, SMB 3.x channel binding.
    public Session bind(Session session, Signatory signatory) throws IOException {
        return bind(session, signatory, true, null);
    }

    Session bind(Session session, Signatory signatory, boolean ownsTransport, Session auxiliary) throws IOException {
        if (ownsTransport && connection.getOwningSession() != null && connection.getOwningSession() != session) {
            throw new IOException("SMB channel belongs to a different session");
        }
        validateBinding(session);
        ConnectionContext original = session.getConnection().getConnectionContext();
        SMB2Dialect dialect = original.getNegotiatedProtocol().getDialect();
        if (signingAlgorithm(original) == SMB3SigningAlgorithm.AES_GMAC
                && !connection.hasIndependentSigningSession(session)) {
            throw new IOException("GMAC binding nonce uniqueness requires an independent authenticated session");
        }
        boolean bound = false;
        // As in go-smb2 sessionSetupBinding, install established cipher keys before reading binding replies.
        if (!sessionTable.registerSessionIfAbsent(session.getSessionId(), session)) {
            throw new IOException("Connection already contains this SMB session");
        }
        try {
            Authenticator authenticator = getAuthenticator(session.getAuthenticationContext());
            if (authenticator instanceof NtlmAuthenticator && config.getNtlmConfig().isIntegrityEnabled()) {
                authenticator = new NtlmSealer((NtlmAuthenticator) authenticator);
            }
            authenticator.init(config);
            BuilderContext ctx = newContext(session.getAuthenticationContext(), authenticator);
            ctx.sessionId = session.getSessionId();
            SessionContext transcript = new SessionContext();
            transcript.setPreauthIntegrityHashValue(connectionContext.getPreauthIntegrityHashValue());
            processAuthenticationToken(ctx, connectionContext.getGssNegotiateToken());
            for (int exchange = 0; exchange < 16; exchange++) {
                SMB2SessionSetup request = new SMB2SessionSetup(dialect,
                        EnumSet.of(config.isSigningRequired() ? SMB2_NEGOTIATE_SIGNING_REQUIRED : SMB2_NEGOTIATE_SIGNING_ENABLED),
                        connectionContext.getClientCapabilities());
                request.setBinding(true);
                request.setSecurityBuffer(ctx.securityContext);
                request.getHeader().setSessionId(ctx.sessionId);
                SMB2Packet wire = signatory.sign(request, session.getSessionContext().getSigningKey());
                SMB2SessionSetup response = signingAlgorithm(original) == SMB3SigningAlgorithm.AES_GMAC
                        ? connection.sendAndReceive(wire, messageId -> session.reserveOriginalKeyMessageId(connection, messageId, false))
                        : connection.sendAndReceive(wire);
                if (dialect == SMB2Dialect.SMB_3_1_1) updatePreauthIntegrityValue(ctx, transcript, wire);
                if (response.getHeader().getSessionId() != ctx.sessionId) {
                    throw new IOException("SMB binding response changed SessionId");
                }
                long status = response.getHeader().getStatusCode();
                if ((status == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue() || status == NtStatus.STATUS_SUCCESS.getValue())
                        && (response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST)
                        || response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL))) {
                    throw new IOException("SMB channel binding changed the authenticated session to guest or anonymous");
                }
                if (status == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue()) {
                    verifySessionSetupResponse(response, session.getSessionContext().getSigningKey(), signatory, "channel binding", exchange + 1);
                    if (dialect == SMB2Dialect.SMB_3_1_1) updatePreauthIntegrityValue(ctx, transcript, response);
                    processAuthenticationToken(ctx, response.getSecurityBuffer());
                    connection.sessionSetupAccepted(response);
                } else if (status == NtStatus.STATUS_SUCCESS.getValue()) {
                    processAuthenticationToken(ctx, response.getSecurityBuffer());
                    if (ctx.sessionKey == null || ctx.sessionKey.length == 0) {
                        throw new IOException("SMB binding authentication did not export a channel key");
                    }
                    // The binding GSS context supplies the channel KDF key; established session cipher keys stay unchanged.
                    SecretKey channelKey = deriveKey(new SecretKeySpec(java.util.Arrays.copyOf(ctx.sessionKey, 16), HMAC_SHA256_ALGORITHM),
                            dialect == SMB2Dialect.SMB_3_1_1 ? KDF_SIGN_LABEL_SMB311 : KDF_SIGN_LABEL,
                            dialect == SMB2Dialect.SMB_3_1_1 ? transcript.getPreauthIntegrityHashValue() : KDF_SIGN_CONTEXT,
                            dialect == SMB2Dialect.SMB_3_1_1 ? signingAlgorithm() : AES_128_CMAC_ALGORITHM);
                    verifySessionSetupResponse(response, channelKey, signatory, "channel binding", exchange + 1);
                    connection.sessionSetupAccepted(response);
                    if (auxiliary != null) auxiliary.close();
                    if (ownsTransport) session.addChannel(connection, channelKey);
                    else session.addBorrowedChannel(connection, channelKey);
                    bound = true;
                    return session;
                } else {
                    if (response.getHeader().isFlagSet(com.hierynomus.mssmb2.SMB2MessageFlag.SMB2_FLAGS_SIGNED)) {
                        verifySessionSetupResponse(response, session.getSessionContext().getSigningKey(), signatory,
                                "channel binding", exchange + 1);
                        connection.sessionSetupAccepted(response);
                    }
                    throw new SMBApiException(response.getHeader(), "SMB channel binding failed");
                }
            }
            throw new IOException("SMB channel binding exceeded authentication exchange limit");
        } catch (SpnegoException e) {
            throw new IOException("SMB channel authentication failed", e);
        } finally {
            if (!bound) {
                sessionTable.removeSession(session.getSessionId(), session);
            }
        }
    }

    public void reauthenticate(Session session, Signatory signatory) throws IOException {
        SMB2Dialect dialect = connectionContext.getNegotiatedProtocol().getDialect();
        if (!dialect.isSmb3x() || !config.isSigningEnabled() || !connection.isConnected()
                || !connection.isSessionEstablished(session) || session.isGuest() || session.isAnonymous()
                || session.getSessionContext().getSigningKey() == null) {
            throw new IOException("Reauthentication requires an active authenticated SMB 3.x signing session");
        }
        try {
            Authenticator authenticator = getAuthenticator(session.getAuthenticationContext());
            if (authenticator instanceof NtlmAuthenticator && config.getNtlmConfig().isIntegrityEnabled()) {
                authenticator = new NtlmSealer((NtlmAuthenticator) authenticator);
            }
            try (java.io.Closeable cleanup = authenticator instanceof java.io.Closeable
                    ? (java.io.Closeable) authenticator : null) {
                authenticator.init(config);
                BuilderContext ctx = newContext(session.getAuthenticationContext(), authenticator);
                processAuthenticationToken(ctx, connectionContext.getGssNegotiateToken());
                for (int exchange = 0; exchange < 16; exchange++) {
                    SMB2SessionSetup request = new SMB2SessionSetup(dialect,
                            EnumSet.of(config.isSigningRequired() ? SMB2_NEGOTIATE_SIGNING_REQUIRED : SMB2_NEGOTIATE_SIGNING_ENABLED),
                            connectionContext.getClientCapabilities());
                    request.getHeader().setSessionId(session.getSessionId());
                    request.setSecurityBuffer(ctx.securityContext);
                    SecretKey key = session.getSigningKey(request.getHeader(), false, connection);
                    SMB2SessionSetup response = connection.sendAndReceive(session, request);
                    if (response.getHeader().getSessionId() != session.getSessionId()) {
                        throw new IOException("SMB reauthentication response changed SessionId");
                    }
                    verifySessionSetupResponse(response, key, signatory, "reauthentication", exchange + 1);
                    long status = response.getHeader().getStatusCode();
                    if (status == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue() || status == NtStatus.STATUS_SUCCESS.getValue()) {
                        if (response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST)
                                || response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL)) {
                            throw new IOException("SMB reauthentication changed the session to guest or anonymous");
                        }
                        processAuthenticationToken(ctx, response.getSecurityBuffer());
                        if (status == NtStatus.STATUS_SUCCESS.getValue()) {
                            if (ctx.sessionKey == null || ctx.sessionKey.length == 0) {
                                throw new IOException("SMB reauthentication did not export an authenticated key");
                            }
                            // Reauthentication validates credentials; established session/channel keys and MID state remain live.
                            connection.sessionSetupAccepted(response);
                            return;
                        }
                        connection.sessionSetupAccepted(response);
                    } else {
                        connection.sessionSetupAccepted(response);
                        throw new SMBApiException(response.getHeader(), "SMB reauthentication failed");
                    }
                }
                throw new IOException("SMB reauthentication exceeded authentication exchange limit");
            }
        } catch (SpnegoException failure) {
            throw new IOException("SMB reauthentication failed", failure);
        }
    }

    void validateBinding(Session session) throws IOException {
        ConnectionContext original = session.getConnection().getConnectionContext();
        SMB2Dialect dialect = original.getNegotiatedProtocol().getDialect();
        if (!dialect.isSmb3x()
                || connectionContext.getNegotiatedProtocol().getDialect() != dialect
                || !original.getServerGuid().equals(connectionContext.getServerGuid())
                || !original.getClientGuid().equals(connectionContext.getClientGuid())
                || original.getCipherId() != connectionContext.getCipherId()
                || signingAlgorithm(original) != signingAlgorithm(connectionContext)
                || original.isServerRequiresSigning() != connectionContext.isServerRequiresSigning()
                || !connectionContext.getServerCapabilities().contains(com.hierynomus.mssmb2.SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL)
                || !config.isSigningEnabled()
                || session.isGuest() || session.isAnonymous() || session.getSessionContext().getSigningKey() == null) {
            throw new IOException("SMB channel does not match the established authenticated SMB 3.x server/session policy");
        }
        session.validateChannelLimits(connectionContext.getNegotiatedProtocol());
        if (sessionTable.find(session.getSessionId()) != null) {
            throw new IOException("Connection already contains this SMB session");
        }
    }

    private void verifySessionSetupResponse(SMB2SessionSetup response, SecretKey key, Signatory signatory,
            String phase, int exchange) throws IOException {
        try {
            boolean signed = response.getHeader().isFlagSet(com.hierynomus.mssmb2.SMB2MessageFlag.SMB2_FLAGS_SIGNED);
            if (!signed || key == null || !signatory.verify(new com.hierynomus.mssmb2.SMB2PacketData(Packets.getPacketBytes(response)), key)) {
                throw new IOException(String.format("SMB %s response signature is %s "
                                + "(exchange=%d, status=0x%08x, flags=0x%08x, messageId=%d)",
                        phase, signed ? "invalid" : "missing", exchange, response.getHeader().getStatusCode(),
                        response.getHeader().getFlags(), response.getHeader().getMessageId()));
            }
        } catch (Buffer.BufferException e) {
            throw new IOException("Malformed SMB " + phase + " response (exchange=" + exchange + ")", e);
        }
    }
    // CUSTOM ADDED END

    private BuilderContext newContext(AuthenticationContext authContext, Authenticator authenticator) {
        BuilderContext ctx = new BuilderContext();
        ctx.authenticator = authenticator;
        ctx.authContext = authContext;
        return ctx;
    }

    private Session setupSession(BuilderContext ctx) throws IOException {
        if (ctx.exchange == 16) throw new IOException("SMB authentication exceeded exchange limit");
        ctx.exchange++;
        initiateSessionSetup(ctx, ctx.securityContext);
        SMB2SessionSetup response = ctx.response;
        if (ctx.exchange == 1) {
            ctx.sessionId = response.getHeader().getSessionId();
        } else if (ctx.sessionId != response.getHeader().getSessionId()
                && (response.getHeader().getStatusCode() == NtStatus.STATUS_SUCCESS.getValue()
                    || response.getHeader().getStatusCode() == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue())) {
            throw new IOException("Authentication continuation changed SessionId");
        }
        SMB2Dialect dialect = connectionContext.getNegotiatedProtocol().getDialect();
        if (response.getHeader().getStatusCode() == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue()) {
            if (dialect == SMB2Dialect.SMB_3_1_1) {
                Session preauthSession = ctx.session;
                if (preauthSession == null) {
                    preauthSession = newSession(ctx);
                    if (!preauthSessionTable.registerSessionIfAbsent(ctx.sessionId, preauthSession)) {
                        throw new IOException("Authentication returned an already provisional SessionId");
                    }
                }
                updatePreauthIntegrityValue(ctx, preauthSession.getSessionContext(), ctx.request);
                updatePreauthIntegrityValue(ctx, preauthSession.getSessionContext(), ctx.response);
            }
            logger.debug("More processing required for authentication of {} using {}", ctx.authContext.getUsername(), ctx.authenticator);
            processAuthenticationToken(ctx, response.getSecurityBuffer());
            connection.sessionSetupAccepted(response);
            return setupSession(ctx);
        } else if (response.getHeader().getStatusCode() != NtStatus.STATUS_SUCCESS.getValue()) {
            connection.sessionSetupAccepted(response);
            throw new SMBApiException(response.getHeader(), format("Authentication failed for '%s' using %s", ctx.authContext.getUsername(), ctx.authenticator));
        } else {
            Session session = ctx.session;
            if (session == null) session = newSession(ctx);

            SessionContext context = session.getSessionContext();
            processAuthenticationToken(ctx, response.getSecurityBuffer());
            boolean unauthenticated = response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST)
                    || response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL);
            if (!unauthenticated && (ctx.sessionKey == null || ctx.sessionKey.length == 0)) {
                throw new IOException("SMB authentication did not export a session key");
            }
            if (ctx.sessionKey != null && ctx.sessionKey.length > 0) {
                context.setSessionKey(new SecretKeySpec(java.util.Arrays.copyOf(ctx.sessionKey, 16), HMAC_SHA256_ALGORITHM));
            }
            if (dialect == SMB2Dialect.SMB_3_1_1) {
                updatePreauthIntegrityValue(ctx, context, ctx.request);
            }
            deriveKeys(response, dialect, context);
            verifySessionSetupSignature(ctx, session, dialect);
            validateAndSetSigning(ctx, context);

            if (dialect == SMB2Dialect.SMB_3_1_1 || !unauthenticated
                    || response.getHeader().isFlagSet(com.hierynomus.mssmb2.SMB2MessageFlag.SMB2_FLAGS_SIGNED)) {
                verifySessionSetupResponse(response, dialect.isSmb3x() ? context.getSigningKey() : context.getSessionKey(),
                        new PacketSignatory(config.getSecurityProvider()), "authentication", ctx.exchange);
            }

            context.established(response);
            connection.sessionSetupAccepted(response);
            session.initializeOriginalKeyMessageIdReservation(connection.nextMessageId());
            return session;
        }
    }

    private Session newSession(BuilderContext ctx) {
        Session preauthSession;
        preauthSession = sessionFactory.createSession(ctx.authContext);
        ctx.session = preauthSession;
        preauthSession.setSessionId(ctx.sessionId);
        preauthSession.getSessionContext().setPreauthIntegrityHashValue(connectionContext.getPreauthIntegrityHashValue());
        return preauthSession;
    }

    private void processAuthenticationToken(BuilderContext ctx, byte[] inputToken) throws IOException {
        AuthenticateResponse resp = ctx.authenticator.authenticate(ctx.authContext, inputToken, connectionContext);
        if (resp == null) {
            return;
        }
        connectionContext.setWindowsVersion(resp.getWindowsVersion());
        connectionContext.setNetBiosName(resp.getNetBiosName());

        ctx.sessionKey = resp.getSessionKey();

        SpnegoToken token = resp.getNegToken();
        Buffer.PlainBuffer negTokenBuffer = new Buffer.PlainBuffer(Endian.LE);
        try {
            token.write(negTokenBuffer);
        } catch (SpnegoException e) {
            throw new IOException(e);
        }
        ctx.securityContext = negTokenBuffer.getCompactData();
    }

    private BuilderContext initiateSessionSetup(BuilderContext ctx, byte[] securityContext) throws TransportException {
        SMB2SessionSetup req = new SMB2SessionSetup(
            connectionContext.getNegotiatedProtocol().getDialect(),
            config.isSigningRequired() || connectionContext.isServerRequiresSigning() ? EnumSet.of(SMB2_NEGOTIATE_SIGNING_REQUIRED) : EnumSet.of(SMB2_NEGOTIATE_SIGNING_ENABLED),
            connectionContext.getClientCapabilities());
        req.setSecurityBuffer(securityContext);
        req.getHeader().setSessionId(ctx.sessionId);
        ctx.request = req;
        ctx.response = connection.sendAndReceive(req);
        return ctx;
    }

    private Authenticator getAuthenticator(AuthenticationContext context) throws SpnegoException {
        List<Factory.Named<Authenticator>> supportedAuthenticators = new ArrayList<>(config.getSupportedAuthenticators());
        List<ASN1ObjectIdentifier> mechTypes = new ArrayList<>();
        if (connectionContext.getGssNegotiateToken().length > 0) {
            // The response NegTokenInit is a NegTokenInit2 according to MS-SPNG.
            NegTokenInit negTokenInit = new NegTokenInit2().read(connectionContext.getGssNegotiateToken());
            mechTypes = negTokenInit.getSupportedMechTypes();
        }

        for (Factory.Named<Authenticator> factory : new ArrayList<>(supportedAuthenticators)) {
            if (mechTypes.isEmpty() || mechTypes.contains(new ASN1ObjectIdentifier(factory.getName()))) {
                Authenticator authenticator = factory.create();
                if (authenticator.supports(context)) {
                    return authenticator;
                }
            }
        }

        throw new SMBRuntimeException("Could not find a configured authenticator for mechtypes: " + mechTypes + " and authentication context: " + context);
    }

    private void validateAndSetSigning(BuilderContext ctx, SessionContext context) {
        boolean requireMessageSigning = config.isSigningRequired();
        boolean connectionSigningRequired = connection.getConnectionContext().isServerRequiresSigning();

        if ((requireMessageSigning || connectionSigningRequired) && !ctx.authContext.isAnonymous() && !ctx.authContext.isGuest()) {
            if (ctx.response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST)) {
                throw new SMB2GuestSigningRequiredException();
            }
            if (ctx.response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL)) {
                throw new SMBRuntimeException("SESSION_SETUP response cannot establish an anonymous session when signing is required");
            }
        }

        // If the global setting RequireMessageSigning is set to TRUE or
        // Connection.RequireSigning is set to TRUE then Session.SigningRequired MUST be
        // set to TRUE, otherwise Session.SigningRequired MUST be set to FALSE.
        context.setSigningRequired(requireMessageSigning || connectionSigningRequired);

        if (ctx.response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL)) {
            // If the security subsystem indicates that the session was established by an anonymous user, Session.SigningRequired MUST be set to FALSE.
            context.setSigningRequired(false);
        }

        boolean guest = ctx.response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST);
        if (guest && context.isSigningRequired()) {
            throw new SMB2GuestSigningRequiredException();
        } else if (guest && !requireMessageSigning) {
            context.setSigningRequired(false);
        }

        if (connection.getNegotiatedProtocol().getDialect().isSmb3x()
            && connection.getConnectionContext().supportsEncryption()
            && ctx.response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_ENCRYPT_DATA)) {
            context.setEncryptData(true);
            context.setSigningRequired(false);
        }
    }

    private void verifySessionSetupSignature(BuilderContext ctx, Session session, SMB2Dialect dialect) {
        if (!config.isSigningEnabled()) {
            return;
        }
        SMB2SessionSetup response = ctx.response;
        boolean guest = response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST);
        boolean anonymous = response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL);
        boolean signatureRequired = !ctx.authContext.isAnonymous() && !ctx.authContext.isGuest()
            && (config.isSigningRequired() || connectionContext.isServerRequiresSigning()
                || (dialect == SMB2Dialect.SMB_3_1_1 && !guest && !anonymous));
        if (!response.getHeader().isFlagSet(SMB2_FLAGS_SIGNED)) {
            if (signatureRequired) {
                if (guest) {
                    throw new SMB2GuestSigningRequiredException();
                }
                if (anonymous) {
                    throw new SMBRuntimeException("Server answered with an anonymous (null) session that cannot be verified while signing is required");
                }
                throw new SMBRuntimeException("SESSION_SETUP response signature verification failed: response is not signed");
            }
            return;
        }

        SecretKey signingKey = session.getSigningKey(response.getHeader(), false);
        if (signingKey == null && dialect.isSmb3x() && session.getSessionContext().getSessionKey() != null) {
            // Unverified guest/null flags must not prevent verification with the authentication key.
            signingKey = deriveSigningKey(dialect, session.getSessionContext());
        }
        if (signingKey == null) {
            if (signatureRequired) {
                throw new SMBRuntimeException("SESSION_SETUP response signature verification failed: no signing key");
            }
            return;
        }

        try {
            SMB2PacketData packetData = new SMB2PacketData(Packets.getPacketBytes(response));
            if (!new PacketSignatory(config.getSecurityProvider()).verify(packetData, signingKey)) {
                throw new SMBRuntimeException("SESSION_SETUP response signature verification failed");
            }
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException("SESSION_SETUP response signature verification failed", e);
        }
    }

    private void updatePreauthIntegrityValue(BuilderContext ctx, SessionContext sessionContext, SMB2Packet packet) {
        if (ctx.digest == null) {
            String algorithmName = connection.getConnectionContext().getPreauthIntegrityHashId().getAlgorithmName();
            try {
                ctx.digest = config.getSecurityProvider().getDigest(algorithmName);
            } catch (SecurityException se) {
                throw new SMBRuntimeException("Cannot get the message digest for " + algorithmName, se);
            }
        }

        sessionContext.setPreauthIntegrityHashValue(DigestUtil.digest(ctx.digest, sessionContext.getPreauthIntegrityHashValue(), Packets.getPacketBytes(packet)));
    }

    private void deriveKeys(SMB2SessionSetup response, SMB2Dialect dialect, SessionContext context) {
        if (dialect.isSmb3x() && context.getSessionKey() != null &&
            !response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL) &&
            !response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST)) {
            // derive signingKey
            context.setSigningKey(deriveSigningKey(dialect, context));
            // derive other key if encryption supported
            if (connectionContext.supportsEncryption()) {
                String alg = connectionContext.getCipherId().getAlgorithmName();
                if (dialect == SMB2Dialect.SMB_3_1_1) {
                    context.setEncryptionKey(deriveKey(context.getSessionKey(), KDF_ENC_LABEL_SMB311, context.getPreauthIntegrityHashValue(), alg));
                    context.setDecryptionKey(deriveKey(context.getSessionKey(), KDF_DEC_LABEL_SMB311, context.getPreauthIntegrityHashValue(), alg));
                    context.setApplicationKey(deriveKey(context.getSessionKey(), KDF_APP_LABEL_SMB311, context.getPreauthIntegrityHashValue(), alg));
                } else {
                    context.setEncryptionKey(deriveKey(context.getSessionKey(), KDF_ENCDEC_LABEL, KDF_ENC_CONTEXT, alg));
                    context.setDecryptionKey(deriveKey(context.getSessionKey(), KDF_ENCDEC_LABEL, KDF_DEC_CONTEXT, alg));
                    context.setApplicationKey(deriveKey(context.getSessionKey(), KDF_APP_LABEL, KDF_APP_CONTEXT, alg));
                }
            }
        }
    }

    private SecretKey deriveSigningKey(SMB2Dialect dialect, SessionContext context) {
        if (dialect == SMB2Dialect.SMB_3_1_1) {
            return deriveKey(context.getSessionKey(), KDF_SIGN_LABEL_SMB311, context.getPreauthIntegrityHashValue(), signingAlgorithm());
        }
        return deriveKey(context.getSessionKey(), KDF_SIGN_LABEL, KDF_SIGN_CONTEXT, AES_128_CMAC_ALGORITHM);
    }

    private static SMB3SigningAlgorithm signingAlgorithm(ConnectionContext context) {
        return context.getSigningAlgorithm() == null ? SMB3SigningAlgorithm.AES_CMAC : context.getSigningAlgorithm();
    }

    private String signingAlgorithm() {
        return signingAlgorithm(connectionContext).getAlgorithmName();
    }

    private SecretKey deriveKey(SecretKey derivationKey, byte[] label, byte[] context, String algorithm) {
        ByteArrayOutputStream fixedSuffixTemp = new ByteArrayOutputStream(25);
        try {
            fixedSuffixTemp.write(label);
            fixedSuffixTemp.write(0);
            fixedSuffixTemp.write(context);
            fixedSuffixTemp.write(new byte[]{0x0, 0x0, 0x0, (byte) 0x80}); // 128 bits (BE byte order)
        } catch (IOException e) {
            logger.error("Unable to format suffix, error occur : ", e);
            return null;
        }
        try {
            DerivationFunction kdf = config.getSecurityProvider().getDerivationFunction("KDF/Counter/HMACSHA256");
            byte[] fixedSuffix = fixedSuffixTemp.toByteArray();
            kdf.init(new CounterDerivationParameters(derivationKey.getEncoded(), fixedSuffix, 32));
            byte[] derived = new byte[16]; // 16 bytes = 128 bits
            kdf.generateBytes(derived, 0, derived.length);
            return new SecretKeySpec(derived, algorithm);
        } catch (SecurityException se) {
            throw new SMBRuntimeException(se);
        }
    }

    public interface SessionFactory {
        Session createSession(AuthenticationContext context);
    }

    public static class BuilderContext {
        private int exchange;
        private Session session;
        private Authenticator authenticator;
        private long sessionId;
        private byte[] sessionKey;
        private AuthenticationContext authContext;
        private byte[] securityContext;
        private SMB2SessionSetup request;
        private SMB2SessionSetup response;
        private MessageDigest digest;
    }
}

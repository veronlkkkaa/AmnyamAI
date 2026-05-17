package com.example.amnyamai.ui.viewmodel

import android.app.Application
import android.content.Context
import android.util.Log
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.IntentSenderRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.amnyamai.data.local.UserStorage
import com.example.amnyamai.data.model.User
import com.example.amnyamai.data.remote.RetrofitClient
import com.example.amnyamai.utils.GoogleConfig
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.AuthorizationResult
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.api.Scope
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private const val TAG = "GoogleAuth"

sealed class RegisterState {
    object Idle : RegisterState()
    object Loading : RegisterState()
    data class Error(val message: String) : RegisterState()
}

class RegisterViewModel(application: Application) : AndroidViewModel(application) {

    private val storage = UserStorage(application)

    private val _registered = MutableStateFlow(storage.isRegistered())
    val registered: StateFlow<Boolean> = _registered

    private val _registerState = MutableStateFlow<RegisterState>(RegisterState.Idle)
    val registerState: StateFlow<RegisterState> = _registerState

    val currentUser get() = storage.getUser()

    data class GooglePrefill(
        val name: String,
        val lastName: String,
        val email: String,
        val idToken: String?,
        val serverAuthCode: String?
    )

    private val _googlePrefill = MutableStateFlow<GooglePrefill?>(null)
    val googlePrefill: StateFlow<GooglePrefill?> = _googlePrefill

    private var pendingPrefill: GooglePrefill? = null

    fun startGoogleSignIn(
        context: Context,
        authLauncher: ActivityResultLauncher<IntentSenderRequest>
    ) {
        Log.d(TAG, "startGoogleSignIn: старт")
        printSignature(context)
        _registerState.value = RegisterState.Loading
        viewModelScope.launch {
            try {
                val option = GetSignInWithGoogleOption.Builder(GoogleConfig.WEB_CLIENT_ID).build()
                val request = GetCredentialRequest.Builder().addCredentialOption(option).build()

                Log.d(TAG, "startGoogleSignIn: запрашиваем credential у CredentialManager")
                val credResult = CredentialManager.create(context).getCredential(context, request)

                Log.d(TAG, "startGoogleSignIn: credential получен, type=${credResult.credential.type}")
                val googleCred = GoogleIdTokenCredential.createFrom(credResult.credential.data)

                Log.d(TAG, "startGoogleSignIn: givenName=${googleCred.givenName}, familyName=${googleCred.familyName}, email=${googleCred.id}")
                Log.d(TAG, "startGoogleSignIn: idToken=${if (googleCred.idToken != null) "получен (${googleCred.idToken.length} chars)" else "NULL"}")

                val prefill = GooglePrefill(
                    name = googleCred.givenName ?: "",
                    lastName = googleCred.familyName ?: "",
                    email = googleCred.id,
                    idToken = googleCred.idToken,
                    serverAuthCode = null
                )
                pendingPrefill = prefill

                Log.d(TAG, "startGoogleSignIn: запрашиваем serverAuthCode через Authorization API")
                val authRequest = AuthorizationRequest.builder()
                    // forceCodeForRefreshToken=true: ensures we can obtain a refresh token even if
                    // the user has already granted access before (helps when scopes change).
                    .requestOfflineAccess(GoogleConfig.WEB_CLIENT_ID, true)
                    .setRequestedScopes(
                        listOf(
                            Scope("email"),
                            Scope("profile"),
                            Scope("https://www.googleapis.com/auth/calendar.events"),
                        )
                    )
                    .build()

                val authResult = Identity.getAuthorizationClient(context)
                    .authorize(authRequest)
                    .awaitTask()

                Log.d(TAG, "startGoogleSignIn: Authorization API ответ — serverAuthCode=${if (authResult.serverAuthCode != null) "получен" else "null"}, hasResolution=${authResult.hasResolution()}")

                when {
                    authResult.serverAuthCode != null -> {
                        Log.d(TAG, "startGoogleSignIn: serverAuthCode получен сразу, показываем форму")
                        _googlePrefill.value = prefill.copy(serverAuthCode = authResult.serverAuthCode)
                        _registerState.value = RegisterState.Idle
                    }
                    authResult.hasResolution() -> {
                        Log.d(TAG, "startGoogleSignIn: нужен IntentSender — запускаем диалог согласия")
                        authLauncher.launch(
                            IntentSenderRequest.Builder(authResult.pendingIntent!!.intentSender).build()
                        )
                        _registerState.value = RegisterState.Idle
                    }
                    else -> {
                        Log.w(TAG, "startGoogleSignIn: serverAuthCode недоступен и нет resolution — показываем форму без него")
                        _googlePrefill.value = prefill
                        _registerState.value = RegisterState.Idle
                    }
                }

            } catch (e: GetCredentialCancellationException) {
                Log.w(TAG, "startGoogleSignIn: пользователь отменил вход или ошибка конфигурации (SHA-1/Client ID)", e)
                _registerState.value = RegisterState.Error(
                    "Вход отменен. Если вы не отменяли вход сами, проверьте SHA-1 и packageName в Google Cloud Console."
                )
            } catch (e: GetCredentialException) {
                Log.e(TAG, "startGoogleSignIn: GetCredentialException — type=${e.type}", e)
                _registerState.value = RegisterState.Error("Ошибка входа через Google: ${e.message}")
            } catch (e: Exception) {
                Log.e(TAG, "startGoogleSignIn: неожиданная ошибка", e)
                _registerState.value = RegisterState.Error("Ошибка: ${e.message}")
            }
        }
    }

    fun onAuthorizationResult(authResult: AuthorizationResult) {
        val prefill = pendingPrefill
        val code = authResult.serverAuthCode
        Log.d(TAG, "onAuthorizationResult: serverAuthCode=${if (code != null) "получен" else "null"}")

        if (code == null) {
            onError("Не удалось получить код от Google")
            return
        }

        _registerState.value = RegisterState.Loading
        viewModelScope.launch {
            try {
                val res = RetrofitClient.apiService.googleCallback(code)
                if (res.isSuccessful && res.body() != null) {
                    val body = res.body()!!
                    storage.saveToken(body.access_token)
                    RetrofitClient.setToken(body.access_token)
                    
                    storage.saveUser(
                        User(
                            name = prefill?.name ?: "User",
                            lastName = prefill?.lastName ?: "",
                            login = body.user.id,
                            isCalendarConnected = true,
                            backendId = body.user.id
                        )
                    )
                    _registerState.value = RegisterState.Idle
                    _registered.value = true
                    } else {
                        Log.d(TAG, "onAuthorizationResult: сервер не авторизовал сразу (код ${res.code()}), показываем форму")
                        _googlePrefill.value = prefill?.copy(serverAuthCode = code) ?: GooglePrefill(
                            name = "", lastName = "", email = "", serverAuthCode = code, idToken = null
                        )
                        _registerState.value = RegisterState.Idle
                    }
            } catch (e: Exception) {
                Log.e(TAG, "onAuthorizationResult: ошибка связи с сервером", e)
                _googlePrefill.value = prefill?.copy(serverAuthCode = code)
                _registerState.value = RegisterState.Idle
            }
        }
    }

    fun onAuthCancelled() {
        Log.d(TAG, "onAuthCancelled: пользователь отменил или ошибка в IntentSender")
        _registerState.value = RegisterState.Idle
    }

    fun onError(message: String) {
        Log.e(TAG, "onError: $message")
        _registerState.value = RegisterState.Error(message)
    }

    fun register(name: String, lastName: String, login: String) {
        val google = _googlePrefill.value
        Log.d(TAG, "register: name='$name', lastName='$lastName', login='$login'")
        Log.d(TAG, "register: serverAuthCode=${if (google?.serverAuthCode != null) "есть" else "нет — только локальная запись"}")

        if (google?.serverAuthCode == null) {
            storage.saveUser(
                User(
                    name = name.trim(),
                    lastName = lastName.trim(),
                    login = login.trim(),
                    isCalendarConnected = false,
                    googleId = null,
                    googleIdToken = google?.idToken
                )
            )
            Log.d(TAG, "register: локальный пользователь сохранён")
            _registered.value = true
            return
        }

        _registerState.value = RegisterState.Loading
        viewModelScope.launch {
            try {
                Log.d(TAG, "register: вызываем backend /api/v1/auth/google/callback")
                val res = RetrofitClient.apiService.googleCallback(google.serverAuthCode)
                Log.d(TAG, "register: ответ backend — code=${res.code()}, success=${res.isSuccessful}")

                if (res.isSuccessful && res.body() != null) {
                    val body = res.body()!!
                    Log.d(TAG, "register: токен получен, backendId=${body.user.id}")
                    storage.saveToken(body.access_token)
                    RetrofitClient.setToken(body.access_token)
                    storage.saveUser(
                        User(
                            name = name.trim(),
                            lastName = lastName.trim(),
                            login = login.trim(),
                            isCalendarConnected = true,
                            googleIdToken = google.idToken,
                            backendId = body.user.id
                        )
                    )
                    Log.d(TAG, "register: пользователь сохранён")
                    _registerState.value = RegisterState.Idle
                    _registered.value = true
                } else if (res.code() == 409) {
                    Log.w(TAG, "register: 409 Conflict - логин занят")
                    _registerState.value = RegisterState.Error("Этот логин уже занят. Пожалуйста, придумайте другой.")
                } else {
                    val errorBody = res.errorBody()?.string()
                    Log.e(TAG, "register: ошибка backend — code=${res.code()}, errorBody=$errorBody")
                    val msg = buildString {
                        append("Auth error: ")
                        append(res.code())
                        if (!errorBody.isNullOrBlank()) {
                            append("\n")
                            append(errorBody.take(800))
                        }
                    }
                    _registerState.value = RegisterState.Error(msg)
                }
            } catch (e: Exception) {
                Log.e(TAG, "register: ошибка сети", e)
                _registerState.value = RegisterState.Error(e.message ?: "Ошибка подключения")
            }
        }
    }

    private fun printSignature(context: Context) {
        try {
            val packageInfo = if (android.os.Build.VERSION.SDK_INT >= 28) {
                context.packageManager.getPackageInfo(context.packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(context.packageName, android.content.pm.PackageManager.GET_SIGNATURES)
            }
            
            val signatures = if (android.os.Build.VERSION.SDK_INT >= 28) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            signatures?.forEach { signature ->
                val md = java.security.MessageDigest.getInstance("SHA-1")
                val digest = md.digest(signature.toByteArray())
                val sha1 = digest.joinToString(":") { "%02X".format(it) }
                Log.i(TAG, "ТЕКУЩИЙ SHA-1 ПРИЛОЖЕНИЯ: $sha1")
                Log.i(TAG, "ПАКЕТ ПРИЛОЖЕНИЯ: ${context.packageName}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Ошибка при получении SHA-1", e)
        }
    }
}

private suspend fun <T> com.google.android.gms.tasks.Task<T>.awaitTask(): T =
    suspendCancellableCoroutine { cont ->
        addOnSuccessListener { cont.resume(it) }
        addOnFailureListener { cont.resumeWithException(it) }
        addOnCanceledListener { cont.cancel() }
    }

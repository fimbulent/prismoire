function base64urlToBuffer(base64url: string): ArrayBuffer {
	const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
	const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer;
}

function bufferToBase64url(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = '';
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function createPasskey(
	options: PublicKeyCredentialCreationOptions & { challenge: string; user: { id: string; name: string; displayName: string } }
): Promise<Credential> {
	const publicKey: PublicKeyCredentialCreationOptions = {
		...options,
		challenge: base64urlToBuffer(options.challenge as unknown as string),
		user: {
			...options.user,
			id: base64urlToBuffer(options.user.id as unknown as string)
		},
		excludeCredentials: (options.excludeCredentials || []).map((c) => ({
			...c,
			id: base64urlToBuffer(c.id as unknown as string)
		}))
	};

	const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
	if (!credential) throw new Error('Passkey creation cancelled');

	const response = credential.response as AuthenticatorAttestationResponse;
	return {
		id: credential.id,
		rawId: bufferToBase64url(credential.rawId),
		type: credential.type,
		response: {
			attestationObject: bufferToBase64url(response.attestationObject),
			clientDataJSON: bufferToBase64url(response.clientDataJSON)
		}
	} as unknown as Credential;
}

export async function getPasskey(
	options: PublicKeyCredentialRequestOptions & { challenge: string }
): Promise<Credential> {
	const publicKey: PublicKeyCredentialRequestOptions = {
		...options,
		challenge: base64urlToBuffer(options.challenge as unknown as string),
		allowCredentials: (options.allowCredentials || []).map((c) => ({
			...c,
			id: base64urlToBuffer(c.id as unknown as string)
		}))
	};

	const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
	if (!credential) throw new Error('Passkey authentication cancelled');

	const response = credential.response as AuthenticatorAssertionResponse;
	return {
		id: credential.id,
		rawId: bufferToBase64url(credential.rawId),
		type: credential.type,
		response: {
			authenticatorData: bufferToBase64url(response.authenticatorData),
			clientDataJSON: bufferToBase64url(response.clientDataJSON),
			signature: bufferToBase64url(response.signature),
			userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null
		}
	} as unknown as Credential;
}

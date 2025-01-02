import memoize from 'memoizee';
import { getSignedUrl } from '@aws-sdk/cloudfront-signer';
import { S3Handler, type S3HandlerProps } from '@balena/pinejs-webresource-s3';
import type { WebResourceType as WebResource } from '@balena/sbvr-types';

export interface CloudFrontHandlerProps extends S3HandlerProps {
	cfPublicKeyId: string;
	cfSecretKey: string;
	cfDistributionDomain: string;
}

const normalizeHref = (href: string) => {
	return href.split('?', 1)[0];
};

export class CloudFrontHandler extends S3Handler {
	private readonly cfSecretKey: string;
	private readonly cfPublicKeyId: string;
	private readonly cfDistributionDomain: string;

	constructor(cfConfig: CloudFrontHandlerProps) {
		super(cfConfig);
		this.cfSecretKey = cfConfig.cfSecretKey;
		this.cfPublicKeyId = cfConfig.cfPublicKeyId;
		this.cfDistributionDomain = cfConfig.cfDistributionDomain;
	}

	public async onPreRespond(webResource: WebResource): Promise<WebResource> {
		if (webResource.href != null) {
			const fileKey = this.cfGetKeyFromHref(webResource.href);
			webResource.href = await this.cachedCfGetSignedUrl(fileKey);
		}
		return webResource;
	}

	// Memoize expects maxAge in MS and CF signing method in seconds.
	// Normalization to use only seconds and therefore convert here from seconds to MS.
	private cachedCfGetSignedUrl = memoize(this.cfSignUrl, {
		maxAge: this.signedUrlCacheExpireTimeSeconds * 1000,
	});

	private async cfSignUrl(cfFileKey: string): Promise<string> {
		try {
			return getSignedUrl({
				url: `${this.cfDistributionDomain}/${cfFileKey}`,
				keyPairId: this.cfPublicKeyId,
				privateKey: this.cfSecretKey,
				dateLessThan: this.getExpiryDate(),
			});
		} catch (e) {
			console.error('CloudFront signing failed with', e);
			console.error('Trying to serve S3 signed url');
			const s3Key = cfFileKey.split('/').at(-1) ?? cfFileKey;
			return await this.cachedGetSignedUrl(s3Key);
		}
	}

	private getExpiryDate(): string {
		const now = new Date().getTime();
		const expiry = now + this.signedUrlExpireTimeSeconds * 1000;
		return new Date(expiry).toISOString();
	}

	private cfGetKeyFromHref(href: string): string {
		const hrefWithoutParams = normalizeHref(href);
		return hrefWithoutParams
			.split('/')
			.slice(3)
			.filter((part) => part !== '')
			.join('/');
	}
}

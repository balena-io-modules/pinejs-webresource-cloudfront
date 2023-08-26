import {  webResourceHandler } from '@balena/pinejs';
import * as memoize from 'memoizee';
import { getSignedUrl } from '@aws-sdk/cloudfront-signer';
import type { WebResourceType as WebResource } from '@balena/sbvr-types';

interface CloudFrontHandlerProps extends webResourceHandler.S3HandlerProps {
	cfPublicKeyId: string;
	cfSecretKey: string;
	cfDistributionDomain: string;
}

export class CloudFrontHandler extends webResourceHandler.S3Handler {

	private readonly cfSecretKey: string;
	private readonly cfPublicKeyId: string;
	private readonly cfDistributionDomain: string;

	// TODO move S3 handler signedUrl as not private
	private readonly cfSignedUrlExpireTimeSeconds = 86400; // 24h
	private readonly cfSignedUrlCacheExpireTimeSeconds = 82800; // 22h

	constructor(cfConfig: CloudFrontHandlerProps) {
		super(cfConfig);
		this.cfSecretKey = cfConfig.cfSecretKey;
		this.cfPublicKeyId = cfConfig.cfPublicKeyId;
		this.cfDistributionDomain = cfConfig.cfDistributionDomain;
	}

	public async onPreRespond(webResource: WebResource): Promise<WebResource> {
		const fileKey = this.cfGetKeyFromHref(webResource.href);
		webResource.href = this.cachedCfGetSignedUrl(fileKey);
		return webResource;
	}

	// Memoize expects maxAge in MS and CF signing method in seconds.
	// Normalization to use only seconds and therefore convert here from seconds to MS
	private cachedCfGetSignedUrl = memoize(this.cfSignUrl, {
		maxAge: this.cfSignedUrlCacheExpireTimeSeconds * 1000,
	});

	private cfSignUrl(fileKey: string): string {
		return getSignedUrl({
			url: `${this.cfDistributionDomain}/${fileKey}`,
			keyPairId: this.cfPublicKeyId,
			privateKey: this.cfSecretKey,
			dateLessThan: this.getExpiryDate()
		});
	}

	private getExpiryDate(): string {
		const now = new Date().getTime();
		const expiry = now + this.cfSignedUrlExpireTimeSeconds * 1000;
		return (new Date(expiry)).toISOString();
	}

	private cfGetKeyFromHref(href: string): string {
		const hrefWithoutParams = webResourceHandler.normalizeHref(href);
		return hrefWithoutParams.split('/').slice(3).filter(part => part !== '').join('/')
	}
}

package aws

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/hashicorp/aws-sdk-go-base/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/terraform-providers/terraform-provider-aws/aws/internal/tfresource"
)

// Returns true if the error matches all these conditions:
//  * err is of type awserr.Error
//  * Error.Code() matches code
//  * Error.Message() contains message
func isAWSErr(err error, code string, message string) bool {
	return tfawserr.ErrMessageContains(err, code, message)
}

// Returns true if the error matches all these conditions:
//  * err is of type awserr.RequestFailure
//  * RequestFailure.StatusCode() matches status code
// It is always preferable to use isAWSErr() except in older APIs (e.g. S3)
// that sometimes only respond with status codes.
func isAWSErrRequestFailureStatusCode(err error, statusCode int) bool {
	return tfawserr.ErrStatusCodeEquals(err, statusCode)
}

func retryOnAwsCode(code string, f func() (interface{}, error)) (interface{}, error) {
	var resp interface{}
	err := resource.Retry(2*time.Minute, func() *resource.RetryError {
		var err error
		resp, err = f()
		if err != nil {
			if tfawserr.ErrCodeEquals(err, code) {
				return resource.RetryableError(err)
			}
			return resource.NonRetryableError(err)
		}
		return nil
	})

	if tfresource.TimedOut(err) {
		resp, err = f()
	}

	return resp, err
}

// RetryOnAwsCodes retries AWS error codes for one minute
// Note: This function will be moved out of the aws package in the future.
func RetryOnAwsCodes(codes []string, f func() (interface{}, error)) (interface{}, error) {
	var resp interface{}
	err := resource.Retry(1*time.Minute, func() *resource.RetryError {
		var err error
		resp, err = f()
		if err != nil {
			var awsErr awserr.Error
			if errors.As(err, &awsErr) {
				for _, code := range codes {
					if awsErr.Code() == code {
						return resource.RetryableError(err)
					}
				}
			}
			return resource.NonRetryableError(err)
		}
		return nil
	})

	if tfresource.TimedOut(err) {
		resp, err = f()
	}

	return resp, err
}

var encodedFailureMessagePattern = regexp.MustCompile(`(?i)(.*) Encoded authorization failure message: ([\w-]+) ?( .*)?`)

type stsDecoder interface {
	DecodeAuthorizationMessage(input *sts.DecodeAuthorizationMessageInput) (*sts.DecodeAuthorizationMessageOutput, error)
}

// decodeError replaces encoded authorization messages with the
// decoded results
func decodeAWSError(decoder stsDecoder, err error) error {

	if err != nil && decoder != nil {
		groups := encodedFailureMessagePattern.FindStringSubmatch(err.Error())
		if groups != nil && len(groups) > 1 {
			result, decodeErr := decoder.DecodeAuthorizationMessage(&sts.DecodeAuthorizationMessageInput{
				EncodedMessage: aws.String(groups[2]),
			})
			if decodeErr == nil {
				msg := aws.StringValue(result.DecodedMessage)
				return fmt.Errorf("%s Authorization failure message: '%s'%s", groups[1], msg, groups[3])
			}
			log.Printf("[WARN] Attempted to decode authorization message, but received: %v", decodeErr)
		}
	}
	return err
}

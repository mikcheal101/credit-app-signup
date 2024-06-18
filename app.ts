import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb"
import * as crypto from "crypto";


class Validator {

    private body: any = {};
    private valididity: boolean;
    private params: any = {};

    constructor(_body: any) {
        this.body = _body;
        this.valididity = false;
    }

    validate(): void {

        if (!this.body) {

            this.valididity = false;
            throw Error('Username Required!')
        }

        this.params = JSON.parse(this.body);

        if (!this.params.username) {

            this.valididity = false;
            throw Error('Username Required!')
        }

        if (!this.params.password) {
            this.valididity = false;
            throw Error('Password Required!')
        }

        if (this.params.username.length < 10) {
            this.valididity = false;
            throw Error('Username length must be min 10 chars long!')
        }

        if (this.params.password.length < 10) {
            this.valididity = false;
            throw Error('Password length must be min 10 chars long!')
        }

        if (!this.params.username.includes('@')) {
            this.valididity = false;
            throw Error('Username must be an email address!')
        }

        this.valididity = true;
    }

    getParameters(): any {
        return this.params;
    }

    isValid(): boolean {
        return this.valididity;
    }

}

export const lambdaHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {

    let body = ''
    let statusCode = 200
    const headers = { 'Content-Type': 'application/json' }

    let validator: Validator = new Validator(event.body);

    // validate the form
    try {
        validator.validate();
    } catch (error: any) {
        statusCode = 500;
        body = error.message;
    }

    if (validator.isValid()) {
        // fetch the parameters if the validator succeeds
        const params = validator.getParameters();

        // Hash entered password
        const password_hash = crypto
            .createHash('md5')
            .update(params.password)
            .digest('base64');

        let hasAccount: boolean = false;

        const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({ region: "us-east-2" }));

        try {


            /// Query database for user with entered username and hashed password, whom should have a positive status
            const users = await dynamo.send(new ScanCommand({
                TableName: process.env.TABLE_NAME,
                ProjectionExpression: 'auth_id, username',
                FilterExpression:
                    'username = :username AND passwordHash = :password AND isActive = :isActive',
                ExpressionAttributeValues: {
                    ':username': params.username,
                    ':password': password_hash,
                    ':isActive': true
                }
            }));

            hasAccount = users.Items.length > 0;

        } catch (err: any) {
            hasAccount = false;
            statusCode = 400
            body = err.message
            console.log(err.message);
        }

        if (!hasAccount) {
            statusCode = 200;
            body = 'User account does not exist';
        } else {
            statusCode = 200;
            body = `Welcome ${params.username}`;

            // TODO:
            // 2. notify user
        }
    }


    const response = {
        statusCode: statusCode,
        body: body,
        headers: headers
    }

    return response
};

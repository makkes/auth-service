package dynamodb

import (
	"crypto/rsa"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	log "github.com/makkes/golib/logging"
	"github.com/makkes/services.makk.es/auth/persistence"
	"golang.org/x/xerrors"
)

type DynamoDB struct {
	svc   *dynamodb.DynamoDB
	table *string
	log   log.Logger
}

func NewDynamoDB(tableName string) (*DynamoDB, error) {
	logger := log.NewDefaultLevelLogger("DYNAMODB")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-central-1"),
		//Endpoint: aws.String("http://localhost:8000"),
		//LogLevel: aws.LogLevel(aws.LogDebugWithHTTPBody),
	})
	if err != nil {
		logger.Error("Could not create session: %s", err)
		return nil, err
	}
	table := aws.String(tableName)

	svc := dynamodb.New(sess)

	_, err = svc.CreateTable(&dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("appID"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("subID"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("email"),
				AttributeType: aws.String("S"),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("appID"),
				KeyType:       aws.String("HASH"),
			},
			{
				AttributeName: aws.String("subID"),
				KeyType:       aws.String("RANGE"),
			},
		},
		LocalSecondaryIndexes: []*dynamodb.LocalSecondaryIndex{
			{
				IndexName: aws.String("accountByEmail"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("appID"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("email"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String(dynamodb.ProjectionTypeAll),
				},
			},
		},
		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(10),
		},
		TableName: table,
	})
	_, updateTTLError := svc.UpdateTimeToLive(&dynamodb.UpdateTimeToLiveInput{
		TableName: table,
		TimeToLiveSpecification: &dynamodb.TimeToLiveSpecification{
			AttributeName: aws.String("ttl"),
			Enabled:       aws.Bool(true),
		},
	})
	if updateTTLError != nil {
		logger.Warn("Error updating TTL: %v", updateTTLError)
	}

	if err != nil {
		// when a ResourceInUseException occurs we assume the table already exists and continue
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() != dynamodb.ErrCodeResourceInUseException {
			logger.Error("Could not create table: %s", err)
			return nil, err
		}
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var tableStatus *string = nil
	for tableStatus == nil || *tableStatus != "ACTIVE" {
		out, err := svc.DescribeTable(&dynamodb.DescribeTableInput{TableName: table})
		if err != nil {
			logger.Error("Could not retrieve table description: %s", err)
		} else {
			logger.Info("Table status is: %s", *out.Table.TableStatus)
			tableStatus = out.Table.TableStatus
		}
		<-ticker.C
	}

	return &DynamoDB{
		svc:   svc,
		table: table,
		log:   logger,
	}, nil
}

func (d *DynamoDB) GetApp(appID persistence.AppID) *persistence.App {
	d.log.Info("Fetching app by ID %s", appID)
	res, err := d.svc.GetItem(&dynamodb.GetItemInput{
		TableName: d.table,
		Key: map[string]*dynamodb.AttributeValue{
			"appID": {S: aws.String(appID.ID)},
			"subID": {S: aws.String("details")},
		},
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityIndexes),
	})
	if err != nil {
		d.log.Error("Error getting app for ID %s: %s", appID, err)
		return nil
	}

	d.log.Info("Consumed capacity: %s", res.ConsumedCapacity)

	if len(res.Item) == 0 {
		return nil
	}

	app := persistence.App{}
	err = dynamodbattribute.UnmarshalMap(res.Item, &app)
	if err != nil {
		d.log.Error("Error unmarshaling result %v: %s", res, err)
		return nil
	}
	app.PublicKey = app.PrivateKey.EncodePublicKey()
	return &app
}

func (d *DynamoDB) GetApps() []*persistence.App {
	d.log.Info("Fetching all apps")
	res, err := d.svc.Scan(&dynamodb.ScanInput{
		TableName:        d.table,
		FilterExpression: aws.String("subID = :details"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":details": {
				S: aws.String("details"),
			},
		},
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityIndexes),
	})
	if err != nil {
		d.log.Error("Error getting apps: %s", err)
		return nil
	}

	d.log.Info("Consumed capacity for getting apps: %s", res.ConsumedCapacity)

	apps := []*persistence.App{}
	err = dynamodbattribute.UnmarshalListOfMaps(res.Items, &apps)
	if err != nil {
		d.log.Error("Error unmarshaling result %v: %s", res, err)
		return nil
	}
	for _, app := range apps {
		app.PublicKey = app.PrivateKey.EncodePublicKey()
	}
	return apps
}

func (d *DynamoDB) SaveApp(id persistence.AppID, name string, maxAccounts int, allowedOrigin string, mailTemplates persistence.MailTemplates, admins persistence.AppAdmins, privateKey rsa.PrivateKey) (*persistence.App, error) {
	newApp := persistence.App{
		ID:            id,
		Name:          name,
		MaxAccounts:   maxAccounts,
		AllowedOrigin: allowedOrigin,
		MailTemplates: mailTemplates,
		Admins:        admins,
		PrivateKey:    persistence.AppKey{Key: privateKey},
	}
	d.log.Info("Saving app %s", newApp)
	av, err := dynamodbattribute.MarshalMap(newApp)
	if err != nil {
		d.log.Error("Could not marshal app: %s", err)
		return nil, err
	}
	av["subID"] = &dynamodb.AttributeValue{S: aws.String("details")}

	input := &dynamodb.PutItemInput{
		Item:                av,
		TableName:           d.table,
		ConditionExpression: aws.String("attribute_not_exists(#appID) AND attribute_not_exists(#origin)"),
		ExpressionAttributeNames: map[string]*string{
			"#appID":  aws.String("appID"),
			"#origin": aws.String("allowedOrigin"),
		},
	}

	out, err := d.svc.PutItem(input)
	if err != nil {
		d.log.Error("Could not put app item: %s", err)
		return nil, err
	}

	d.log.Info("Consumed capacity: %s", out.ConsumedCapacity)

	newApp.PublicKey = newApp.PrivateKey.EncodePublicKey()
	return &newApp, nil
}

func (d *DynamoDB) App(appID persistence.AppID) persistence.AppContext {
	d.log.Info("Creating app context for app %s", appID)
	return &DynamoDBAppContext{
		db:    d,
		appID: appID,
	}
}

func (d *DynamoDB) DeleteApp(id persistence.AppID) error {
	d.log.Info("Deleting app %s", id)
	res, err := d.svc.DeleteItem(&dynamodb.DeleteItemInput{
		TableName: d.table,
		Key: map[string]*dynamodb.AttributeValue{
			"appID": {
				S: aws.String(id.ID),
			},
			"subID": {
				S: aws.String("details"),
			},
		},
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityIndexes),
	})
	if err != nil {
		d.log.Error("Error deleting app %s: %s", id, err)
		return err
	}

	d.log.Info("Consumed capacity for deleting app: %s", res.ConsumedCapacity)

	accounts := d.App(id).GetAccounts()
	if len(accounts) > 0 {
		for _, account := range accounts {
			res, err := d.svc.DeleteItem(&dynamodb.DeleteItemInput{
				TableName: d.table,
				Key: map[string]*dynamodb.AttributeValue{
					"appID": {
						S: aws.String(id.ID),
					},
					"subID": {
						S: aws.String("account:" + account.ID.UUID.String()),
					},
				},
				ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityIndexes),
			})
			if err != nil {
				d.log.Error("Error deleting account %s after deleting app %s: %s", account.ID, id, err)
			} else {
				d.log.Info("Consumed capacity for deleting account %s after deleting app %s: %s", account.ID, id, res.ConsumedCapacity)
			}
		}
	}

	return nil
}

type DynamoDBAppContext struct {
	db    *DynamoDB
	appID persistence.AppID
}

func (d *DynamoDBAppContext) GetAccountByEmail(email string) *persistence.Account {
	d.db.log.Info("Getting account in app %s by email %s", d.appID.ID, email)
	res, err := d.db.svc.Query(&dynamodb.QueryInput{
		TableName:              d.db.table,
		IndexName:              aws.String("accountByEmail"),
		KeyConditionExpression: aws.String("appID = :appID AND email = :email"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":appID": {
				S: aws.String(d.appID.ID),
			},
			":email": {
				S: aws.String(email),
			},
		},
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityIndexes),
	})
	if err != nil {
		d.db.log.Error("Error getting account for email %s in app %s: %s", email, d.appID, err)
		return nil
	}

	d.db.log.Info("Consumed capacity: %s", res.ConsumedCapacity)

	if len(res.Items) == 0 {
		d.db.log.Info("Found no items in app %s for email %s", d.appID.ID, email)
		return nil
	}
	if len(res.Items) > 1 {
		d.db.log.Info("Found more than one item in app %s for email %s. Returning one of them.", d.appID.ID, email)
	}
	account := persistence.Account{}
	err = dynamodbattribute.UnmarshalMap(res.Items[0], &account)
	if err != nil {
		d.db.log.Error("Error unmarshaling result %v: %s", res, err)
		return nil
	}
	d.db.log.Info("Returning account %s", account.ID)
	return &account
}

func (d *DynamoDBAppContext) SaveAccount(account persistence.Account) error {
	d.db.log.Info("Saving account %s in app %s", account, d.appID.ID)
	av := make(map[string]*dynamodb.AttributeValue)
	av["appID"] = &dynamodb.AttributeValue{S: aws.String(d.appID.ID)}
	av["subID"] = &dynamodb.AttributeValue{S: aws.String("account:" + account.ID.String())}
	av["active"] = &dynamodb.AttributeValue{BOOL: aws.Bool(account.Active)}
	av["email"] = &dynamodb.AttributeValue{S: aws.String(account.Email)}
	roles := make([]*dynamodb.AttributeValue, len(account.Roles))
	for idx, role := range account.Roles {
		roles[idx] = &dynamodb.AttributeValue{S: aws.String(role)}
	}
	av["roles"] = &dynamodb.AttributeValue{L: roles}
	avHash, err := dynamodbattribute.MarshalMap(account.PasswordHash)
	if err != nil {
		return xerrors.Errorf("could not marshal password %v: %w", account.PasswordHash, err)
	}
	av["passwordHash"] = &dynamodb.AttributeValue{M: avHash}

	input := &dynamodb.PutItemInput{
		Item:                   av,
		TableName:              d.db.table,
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityIndexes),
	}

	out, err := d.db.svc.PutItem(input)
	if err != nil {
		return xerrors.Errorf("could not put account item: %w", err)
	}

	d.db.log.Info("Consumed capacity for saving account: %s", out.ConsumedCapacity)
	return nil
}

func (d *DynamoDBAppContext) GetAccount(id persistence.AccountID) *persistence.Account {
	d.db.log.Info("Fetching account in app %s by ID %s", d.appID, id)
	res, err := d.db.svc.GetItem(&dynamodb.GetItemInput{
		TableName: d.db.table,
		Key: map[string]*dynamodb.AttributeValue{
			"appID": {S: aws.String(d.appID.ID)},
			"subID": {S: aws.String("account:" + id.UUID.String())},
		},
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityIndexes),
	})
	if err != nil {
		d.db.log.Error("Error getting account in app %s by ID %s: %s", d.appID, id, err)
		return nil
	}

	d.db.log.Info("Consumed capacity: %s", res.ConsumedCapacity)

	if len(res.Item) == 0 {
		return nil
	}

	account := persistence.Account{}
	err = dynamodbattribute.UnmarshalMap(res.Item, &account)
	if err != nil {
		d.db.log.Error("Error unmarshaling result %v: %s", res, err)
		return nil
	}
	return &account
}

func (d *DynamoDBAppContext) GetAccounts() []*persistence.Account {
	d.db.log.Info("Fetching accounts in app %s", d.appID)
	res, err := d.db.svc.Query(&dynamodb.QueryInput{
		TableName: d.db.table,
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":appID":         {S: aws.String(d.appID.ID)},
			":accountPrefix": {S: aws.String("account:")},
		},
		KeyConditionExpression: aws.String("appID = :appID AND begins_with(subID, :accountPrefix)"),
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityIndexes),
	})
	if err != nil {
		d.db.log.Error("Error getting accounts for app %s: %s", d.appID, err)
		return nil
	}

	d.db.log.Info("Consumed capacity: %s", res.ConsumedCapacity)

	if len(res.Items) == 0 {
		return nil
	}

	accounts := []*persistence.Account{}
	err = dynamodbattribute.UnmarshalListOfMaps(res.Items, &accounts)
	if err != nil {
		d.db.log.Error("Error unmarshaling result %v: %s", res, err)
		return nil
	}
	return accounts
}

func (d *DynamoDBAppContext) DeleteAccount(id persistence.AccountID) error {
	return xerrors.New("This function is not implemented on DynamoDB")
}

func (d *DynamoDBAppContext) SaveActivationToken(accountID persistence.AccountID, token string) error {
	out, err := d.db.svc.UpdateItem(&dynamodb.UpdateItemInput{
		TableName: d.db.table,
		Key: map[string]*dynamodb.AttributeValue{
			"appID": {
				S: aws.String(d.appID.ID),
			},
			"subID": {
				S: aws.String("account:" + accountID.UUID.String()),
			},
		},
		ConditionExpression: aws.String("attribute_exists(subID)"),
		UpdateExpression:    aws.String("SET activationToken = :token"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":token": {S: aws.String(token)},
		},
		ReturnConsumedCapacity:      aws.String(dynamodb.ReturnConsumedCapacityIndexes),
		ReturnItemCollectionMetrics: aws.String(dynamodb.ReturnItemCollectionMetricsSize),
	})

	if err != nil {
		d.db.log.Error("Error saving activation token %s in app %s for account %s: %s", token, d.appID, accountID, err)
		return err
	}
	d.db.log.Info("Consumed capacity for saving activation token: %s", out.ConsumedCapacity)
	d.db.log.Info("Item collection metrics saving activation token: %s", out.ItemCollectionMetrics)

	return nil
}

func (d *DynamoDBAppContext) GetActivationToken(id persistence.AccountID) string {
	d.db.log.Info("Fetching activation token in app %s by ID %s", d.appID, id)
	res, err := d.db.svc.GetItem(&dynamodb.GetItemInput{
		TableName: d.db.table,
		Key: map[string]*dynamodb.AttributeValue{
			"appID": {S: aws.String(d.appID.ID)},
			"subID": {S: aws.String("account:" + id.UUID.String())},
		},
		ProjectionExpression:   aws.String("activationToken"),
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityIndexes),
	})
	if err != nil {
		d.db.log.Error("Error getting activation token in app %s by ID %s: %s", d.appID, id, err)
		return ""
	}

	d.db.log.Info("Consumed capacity: %s", res.ConsumedCapacity)

	var token string
	err = dynamodbattribute.Unmarshal(res.Item["activationToken"], &token)
	if err != nil {
		d.db.log.Error("Error unmarshaling result %v: %s", res, err)
		return ""
	}
	return token
}

func (d *DynamoDBAppContext) DeleteActivationToken(id persistence.AccountID) error {
	out, err := d.db.svc.UpdateItem(&dynamodb.UpdateItemInput{
		TableName: d.db.table,
		Key: map[string]*dynamodb.AttributeValue{
			"appID": {
				S: aws.String(d.appID.ID),
			},
			"subID": {
				S: aws.String("account:" + id.UUID.String()),
			},
		},
		ConditionExpression:         aws.String("attribute_exists(subID)"),
		UpdateExpression:            aws.String("REMOVE activationToken"),
		ReturnConsumedCapacity:      aws.String(dynamodb.ReturnConsumedCapacityIndexes),
		ReturnItemCollectionMetrics: aws.String(dynamodb.ReturnItemCollectionMetricsSize),
	})

	if err != nil {
		d.db.log.Error("Error deleting activation token for account %s in app %s: %s", id, d.appID, err)
		return err
	}
	d.db.log.Info("Consumed capacity for deleting activation token: %s", out.ConsumedCapacity)
	d.db.log.Info("Item collection metrics deleting activation token: %s", out.ItemCollectionMetrics)

	return nil
}

func (d *DynamoDBAppContext) UpdateAppName(newName string) error {
	out, err := d.db.svc.UpdateItem(&dynamodb.UpdateItemInput{
		TableName: d.db.table,
		Key: map[string]*dynamodb.AttributeValue{
			"appID": {
				S: aws.String(d.appID.ID),
			},
			"subID": {S: aws.String("details")},
		},
		ConditionExpression: aws.String("attribute_exists(#appID)"),
		UpdateExpression:    aws.String("SET #name = :n"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":n": {
				S: aws.String(newName),
			},
		},
		ExpressionAttributeNames: map[string]*string{
			"#name":  aws.String("name"),
			"#appID": aws.String("appID"),
		},
		ReturnConsumedCapacity:      aws.String(dynamodb.ReturnConsumedCapacityIndexes),
		ReturnItemCollectionMetrics: aws.String(dynamodb.ReturnItemCollectionMetricsSize),
	})

	if err != nil {
		d.db.log.Error("Error setting app name to '%s' in app %s: %s", newName, d.appID, err)
		return err
	}
	d.db.log.Info("Consumed capacity for updating app name: %s", out.ConsumedCapacity)
	d.db.log.Info("Item collection metrics updating app name: %s", out.ItemCollectionMetrics)

	return nil
}

func (d *DynamoDBAppContext) UpdateAppOrigin(newOrigin string) error {
	out, err := d.db.svc.UpdateItem(&dynamodb.UpdateItemInput{
		TableName: d.db.table,
		Key: map[string]*dynamodb.AttributeValue{
			"appID": {
				S: aws.String(d.appID.ID),
			},
			"subID": {S: aws.String("details")},
		},
		ConditionExpression: aws.String("attribute_exists(#appID)"),
		UpdateExpression:    aws.String("SET #allowedOrigin = :o"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":o": {
				S: aws.String(newOrigin),
			},
		},
		ExpressionAttributeNames: map[string]*string{
			"#allowedOrigin": aws.String("allowedOrigin"),
			"#appID":         aws.String("appID"),
		},
		ReturnConsumedCapacity:      aws.String(dynamodb.ReturnConsumedCapacityIndexes),
		ReturnItemCollectionMetrics: aws.String(dynamodb.ReturnItemCollectionMetricsSize),
	})

	if err != nil {
		d.db.log.Error("Error setting app origin to '%s' in app %s: %s", newOrigin, d.appID, err)
		return err
	}
	d.db.log.Info("Consumed capacity for updating app origin: %s", out.ConsumedCapacity)
	d.db.log.Info("Item collection metrics updating app origin: %s", out.ItemCollectionMetrics)

	return nil
}

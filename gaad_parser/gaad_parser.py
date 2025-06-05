#!/usr/bin/env python3
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import urllib.parse

from pydantic import BaseModel, Field, validator

class HashableModel(BaseModel):
    __hash: str = None
    def __hash__(self):
        if not self.__hash:
            self.__hash = hash(json.dumps(self.model_dump()))
        return self.__hash

class TrustPolicy(HashableModel):
    class Config:
        extra="allow"

class RoleTrustPolicy(HashableModel):
    """Model for a role and its trust policy."""
    roleName: str
    roleId: str
    arn: str
    assumeRolePolicyDocument: TrustPolicy

    def __str__(self):
        return self.model_dump()

class TrustPolicyList(HashableModel):
    class Config:
        extra="allow"

    def __str__(self):
        return self.model_dump()

class AccountAuthorizationDetails(HashableModel):
    """Model for the complete authorization details response."""
    role_detail_list: List[Dict[str, Any]] = Field(alias="RoleDetailList")


class TrustPolicyExtractor:
    """Main class for extracting and processing trust policies."""
    
    def __init__(self, json_file_path: str):
        """
        Initialize the extractor with a JSON file path.
        
        Args:
            json_file_path: Path to the JSON file containing authorization details
        """
        self.json_file_path = Path(json_file_path)
        self.auth_details: Optional[AccountAuthorizationDetails] = None
        self.trust_policies: List[RoleTrustPolicy] = []

    def __str__(self):
        return json.dumps([p.model_dump() for p in self.trust_policies], indent=2, default=str)

    
    def load_json_file(self) -> Dict[str, Any]:
        """
        Load and parse the JSON file.
        
        Returns:
            Dictionary containing the parsed JSON data
            
        Raises:
            FileNotFoundError: If the JSON file doesn't exist
            json.JSONDecodeError: If the file contains invalid JSON
        """
        if not self.json_file_path.exists():
            raise FileNotFoundError(f"JSON file not found: {self.json_file_path}")
        
        try:
            with open(self.json_file_path, 'r') as f:
                data = json.load(f)
            return data
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Invalid JSON in file {self.json_file_path}: {e}")
    
    def parse_authorization_details(self) -> None:
        """Parse the JSON file and create AccountAuthorizationDetails model."""
        json_data = self.load_json_file()
        
        try:
            self.auth_details = AccountAuthorizationDetails(**json_data)
            print(f"Successfully parsed authorization details with {len(self.auth_details.role_detail_list)} roles")
        except Exception as e:
            print(f"Error parsing authorization details: {e}")
            sys.exit(1)
    
    def extract_trust_policies(self) -> None:
        """Extract trust policies from the authorization details and create RoleTrustPolicy models."""
        if not self.auth_details:
            raise ValueError("Authorization details not loaded. Call parse_authorization_details() first.")
        
        for role_data in self.auth_details.role_detail_list:
            try:
                role_name = role_data.get('RoleName', 'Unknown')
                assume_role_policy = role_data.get('AssumeRolePolicyDocument')
                
                if not assume_role_policy:
                    print(f"Warning: No trust policy found for role {role_name}")
                    continue

                trust_policy = TrustPolicy.model_validate(assume_role_policy)
                
                self.trust_policies.append(trust_policy)
                
            except Exception as e:
                print(f"Warning: Could not parse trust policy for role {role_name}: {e}")
                continue
        
        print(f"Successfully extracted {len(self.trust_policies)} trust policies")
    
    def filter_roles(self, role_filter: str) -> List[RoleTrustPolicy]:
        """
        Filter roles by name.
        
        Args:
            role_filter: String to filter role names (case-insensitive partial match)
            
        Returns:
            List of filtered RoleTrustPolicy objects
        """
        return [
            policy for policy in self.trust_policies
            if role_filter.lower() in policy.role_name.lower()
        ]
    
    def get_roles_by_principal_type(self, principal_type: str) -> List[RoleTrustPolicy]:
        """
        Get roles that can be assumed by a specific principal type.
        
        Args:
            principal_type: Type of principal ('Service', 'AWS', 'Federated', etc.)
            
        Returns:
            List of RoleTrustPolicy objects
        """
        matching_roles = []
        
        for role_policy in self.trust_policies:
            for statement in role_policy.trust_policy.statement:
                if isinstance(statement.principal, dict):
                    if principal_type.lower() in [k.lower() for k in statement.principal.keys()]:
                        matching_roles.append(role_policy)
                        break
        
        return matching_roles
    

    def apply_filters(self,filters):
        filtered_policies = self.trust_policies.copy()
        for target,regex in filters:
            if target == "Principal":
                # if one of the trust policies match, filter the whole role
                # TODO: Change this this is literally the worst thing i've ever written
                filtered_policies = [
                    policy for policy in filtered_policies if not any([
                        re.search(regex, json.dumps(statement["Principal"])) for statement in policy.Statement
                    ])
                ]
        print(json.dumps([p.model_dump() for p in filtered_policies], indent=2, default=str))

def interactive_menu(extractor):
    filters = []

    while True:
        try:
            print(f"\nCurrent Filters: {filters}")
            user_input = input("\n> ").strip()

            if user_input.lower() in ['quit', 'exit', 'q']:
                break

            elif user_input.lower() in ['help', 'h']:
                print("Available commands:")
                print("  principal/p <REGEX> - Add regex filter to remove principals with NAME")
                print("  remove/r <n> - remove filter with index <n> (starting from 0)")
                print("  show/s - Show the current policies")
                print("  help/h - Show this help message")
                print("  quit/exit/q - Exit the program")

            elif user_input.lower().split(" ")[0] in ['principal', 'p']:
                regex = " ".join(user_input.split(" ")[1:])
                filters.append(("Principal", regex))

            elif user_input.lower().split(" ")[0] in ['remove', 'r']:
                index = int(" ".join(user_input.split(" ")[1:]))
                del filters[index]

            elif user_input.lower() in ['show', 's']:
                extractor.apply_filters(filters)

        except KeyboardInterrupt:
            break
        except EOFError:
            break
        except Exception as e:
            print(e)
            continue

def main():
    """Main function to orchestrate the trust policy extraction."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Parse IAM Role trust policies from local JSON file'
    )
    parser.add_argument(
        'json_file',
        help='Path to JSON file containing get-account-authorization-details output'
    )
    args = parser.parse_args()
    
    # Initialize extractor
    extractor = TrustPolicyExtractor(args.json_file)
    
    try:
        # Parse the JSON file
        extractor.parse_authorization_details()
        
        # Extract trust policies
        extractor.extract_trust_policies()

        interactive_menu(extractor)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

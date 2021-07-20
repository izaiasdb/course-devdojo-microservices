package br.com.idb.idbcore.repository;


import org.springframework.data.repository.PagingAndSortingRepository;

import br.com.idb.idbcore.model.ApplicationUser;

public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {

    ApplicationUser findByUsername(String username);

}

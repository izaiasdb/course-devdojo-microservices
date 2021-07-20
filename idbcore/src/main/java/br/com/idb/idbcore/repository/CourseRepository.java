package br.com.idb.idbcore.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import br.com.idb.idbcore.model.Course;

public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {
}
